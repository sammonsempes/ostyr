//! SNMP trap parsing: one v1 or v2c trap or inform datagram into a bounded record (spec section 22).

use crate::error::ConfigError;
use crate::model::{
    TrapDrop, TrapKind, TrapLimits, TrapRecord, TrapVarbind, TrapVersion, DIGEST_BYTES, MAX_OID_ARCS, MAX_TRAP_BYTES, MAX_VALUE_CHARS_CEILING,
    MAX_VARBINDS_CEILING,
};
use ecs_normalise::suricata::is_unsafe;
use sha2::{Digest, Sha256};
use snmp_parser::asn1_rs::Err as BerErr;
use snmp_parser::error::SnmpError;
use snmp_parser::{
    parse_snmp_generic_message, NetworkAddress, ObjectSyntax, Oid, PduType, SnmpGenericMessage, SnmpGenericPdu, SnmpMessage, SnmpPdu, SnmpTrapPdu,
    SnmpVariable, TrapType, VarBindValue,
};


const SYS_UPTIME_OID: &str = "1.3.6.1.2.1.1.3.0";


const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1.0";


const SNMP_TRAPS_PREFIX: &str = "1.3.6.1.6.3.1.1.5";


const VERSION_V1: u32 = 0;


fn check(condition: bool, error: ConfigError) -> Result<(), ConfigError> {
    condition.then_some(()).ok_or(error)
}


pub fn validate_trap_limits(limits: &TrapLimits) -> Result<(), ConfigError> {
    check((1..=MAX_VARBINDS_CEILING).contains(&limits.max_varbinds), ConfigError::BadMaxVarbinds)?;
    check(
        (1..=MAX_VALUE_CHARS_CEILING).contains(&limits.max_value_chars),
        ConfigError::BadMaxValueChars,
    )
}


pub fn community_digest(community: &str) -> String {
    let hash = Sha256::digest(community.as_bytes());
    let hex: String = hash.iter().take(DIGEST_BYTES).map(|byte| format!("{byte:02x}")).collect();
    format!("#{hex}")
}


pub fn hex_text(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("hex:{hex}")
}


pub fn octet_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.chars().any(is_unsafe) => text.to_string(),
        _ => hex_text(bytes),
    }
}


pub fn cut_text(text: String, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        text
    } else {
        let kept: String = text.chars().take(max_chars).collect();
        format!("{kept}[cut, {} chars]", total - max_chars)
    }
}


pub fn oid_text(oid: &Oid) -> Result<String, TrapDrop> {
    let arcs = oid.iter().ok_or(TrapDrop::Malformed)?;
    (arcs.len() <= MAX_OID_ARCS).then(|| oid.to_id_string()).ok_or(TrapDrop::Malformed)
}


fn syntax_text(syntax: &ObjectSyntax) -> Result<String, TrapDrop> {
    let text = match syntax {
        ObjectSyntax::Number(number) => number.to_string(),
        ObjectSyntax::String(bytes) => octet_text(bytes),
        ObjectSyntax::Object(oid) => oid_text(oid)?,
        ObjectSyntax::BitString(bits) => hex_text(&bits.data),
        ObjectSyntax::Empty => String::new(),
        ObjectSyntax::UnknownSimple(any) | ObjectSyntax::UnknownApplication(any) => hex_text(any.data),
        ObjectSyntax::IpAddress(NetworkAddress::IPv4(address)) => address.to_string(),
        ObjectSyntax::Counter32(number) | ObjectSyntax::Gauge32(number) | ObjectSyntax::TimeTicks(number) | ObjectSyntax::UInteger32(number) => {
            number.to_string()
        }
        ObjectSyntax::Opaque(bytes) | ObjectSyntax::NsapAddress(bytes) => hex_text(bytes),
        ObjectSyntax::Counter64(number) => number.to_string(),
    };
    Ok(text)
}


pub fn value_text(value: &VarBindValue, max_chars: usize) -> Result<String, TrapDrop> {
    let text = match value {
        VarBindValue::Value(syntax) => syntax_text(syntax)?,
        VarBindValue::Unspecified => "unspecified".to_string(),
        VarBindValue::NoSuchObject => "noSuchObject".to_string(),
        VarBindValue::NoSuchInstance => "noSuchInstance".to_string(),
        VarBindValue::EndOfMibView => "endOfMibView".to_string(),
    };
    Ok(cut_text(text, max_chars))
}


fn varbind_of(variable: &SnmpVariable, max_chars: usize) -> Result<TrapVarbind, TrapDrop> {
    Ok(TrapVarbind {
        oid: oid_text(&variable.oid)?,
        value: value_text(&variable.val, max_chars)?,
    })
}


fn bounded_varbinds(variables: &[SnmpVariable], limits: &TrapLimits) -> Result<(Vec<TrapVarbind>, usize), TrapDrop> {
    let kept = variables
        .iter()
        .take(limits.max_varbinds)
        .map(|variable| varbind_of(variable, limits.max_value_chars))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((kept, variables.len().saturating_sub(limits.max_varbinds)))
}


pub fn v1_trap_oid(enterprise: &str, generic: TrapType, specific: u32) -> Result<String, TrapDrop> {
    if generic == TrapType::ENTERPRISE_SPECIFIC {
        Ok(format!("{enterprise}.0.{specific}"))
    } else if generic.0 <= TrapType::EGP_NEIGHBOR_LOSS.0 {
        Ok(format!("{SNMP_TRAPS_PREFIX}.{}", generic.0 + 1))
    } else {
        Err(TrapDrop::Malformed)
    }
}


fn version_of(message: &SnmpMessage) -> TrapVersion {
    if message.version == VERSION_V1 {
        TrapVersion::V1
    } else {
        TrapVersion::V2c
    }
}


fn v1_record(message: &SnmpMessage, pdu: &SnmpTrapPdu, limits: &TrapLimits) -> Result<TrapRecord, TrapDrop> {
    let enterprise = oid_text(&pdu.enterprise)?;
    let NetworkAddress::IPv4(address) = pdu.agent_addr;
    let (varbinds, varbinds_omitted) = bounded_varbinds(&pdu.var, limits)?;
    Ok(TrapRecord {
        version: version_of(message),
        kind: TrapKind::TrapV1,
        community_digest: community_digest(&message.community),
        trap_oid: v1_trap_oid(&enterprise, pdu.generic_trap, pdu.specific_trap)?,
        agent_address: Some(address),
        uptime_ticks: pdu.timestamp,
        varbinds,
        varbinds_omitted,
    })
}


fn uptime_of(variable: &SnmpVariable) -> Result<u32, TrapDrop> {
    match (oid_text(&variable.oid)?.as_str(), &variable.val) {
        (SYS_UPTIME_OID, VarBindValue::Value(ObjectSyntax::TimeTicks(ticks))) => Ok(*ticks),
        _ => Err(TrapDrop::Malformed),
    }
}


fn trap_oid_of(variable: &SnmpVariable) -> Result<String, TrapDrop> {
    match (oid_text(&variable.oid)?.as_str(), &variable.val) {
        (SNMP_TRAP_OID, VarBindValue::Value(ObjectSyntax::Object(oid))) => oid_text(oid),
        _ => Err(TrapDrop::Malformed),
    }
}


fn v2_record(message: &SnmpMessage, pdu: &SnmpGenericPdu, kind: TrapKind, limits: &TrapLimits) -> Result<TrapRecord, TrapDrop> {
    let (uptime_variable, after_uptime) = pdu.var.split_first().ok_or(TrapDrop::Malformed)?;
    let (trap_variable, rest) = after_uptime.split_first().ok_or(TrapDrop::Malformed)?;
    let (varbinds, varbinds_omitted) = bounded_varbinds(rest, limits)?;
    Ok(TrapRecord {
        version: version_of(message),
        kind,
        community_digest: community_digest(&message.community),
        trap_oid: trap_oid_of(trap_variable)?,
        agent_address: None,
        uptime_ticks: uptime_of(uptime_variable)?,
        varbinds,
        varbinds_omitted,
    })
}


fn record_of(message: &SnmpMessage, limits: &TrapLimits) -> Result<TrapRecord, TrapDrop> {
    match &message.pdu {
        SnmpPdu::TrapV1(pdu) => v1_record(message, pdu, limits),
        SnmpPdu::Generic(pdu) if pdu.pdu_type == PduType::TrapV2 => v2_record(message, pdu, TrapKind::TrapV2, limits),
        SnmpPdu::Generic(pdu) if pdu.pdu_type == PduType::InformRequest => v2_record(message, pdu, TrapKind::Inform, limits),
        SnmpPdu::Generic(_) | SnmpPdu::Bulk(_) => Err(TrapDrop::Unsupported),
    }
}


pub fn drop_of(error: &BerErr<SnmpError>) -> TrapDrop {
    match error {
        BerErr::Error(SnmpError::InvalidPduType) | BerErr::Failure(SnmpError::InvalidPduType) => TrapDrop::Unsupported,
        _ => TrapDrop::Malformed,
    }
}


pub fn parse_trap(datagram: &[u8], limits: &TrapLimits) -> Result<TrapRecord, TrapDrop> {
    (datagram.len() <= MAX_TRAP_BYTES).then_some(()).ok_or(TrapDrop::TooLarge)?;
    let (_, message) = parse_snmp_generic_message(datagram).map_err(|error| drop_of(&error))?;
    match &message {
        SnmpGenericMessage::V1(inner) | SnmpGenericMessage::V2(inner) => record_of(inner, limits),
        SnmpGenericMessage::V3(_) => Err(TrapDrop::Unsupported),
    }
}
