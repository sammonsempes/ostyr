use crate::error::ParseError;
use crate::model::{Posture, ProtectionState, ToolOutputs};
use crate::parse::{parse_filevault, parse_firewall, parse_gatekeeper, parse_sip, REASON_NOT_READ, REASON_TOO_LARGE};


/// An oversized output is `Unknown`, and logged.
pub fn or_unknown(parsed: Result<Posture, ParseError>) -> Posture {
    match parsed {
        Ok(posture) => posture,
        Err(error) => {
            tracing::warn!("protection tool output refused: {error}");
            Posture::Unknown { reason: REASON_TOO_LARGE }
        }
    }
}


/// Gathers the five postures; XProtect is not read in this slice.
pub fn protection_state(outputs: &ToolOutputs) -> ProtectionState {
    ProtectionState {
        filevault: or_unknown(parse_filevault(outputs.fdesetup_status)),
        gatekeeper: or_unknown(parse_gatekeeper(outputs.spctl_status)),
        sip: or_unknown(parse_sip(outputs.csrutil_status)),
        firewall: or_unknown(parse_firewall(outputs.firewall_global_state)),
        xprotect: Posture::Unknown { reason: REASON_NOT_READ },
    }
}


/// Names of the protections whose state is unknown, shown by the platform as blind spots.
pub fn blind_spots(state: &ProtectionState) -> Vec<&'static str> {
    [
        ("filevault", state.filevault),
        ("gatekeeper", state.gatekeeper),
        ("sip", state.sip),
        ("firewall", state.firewall),
        ("xprotect", state.xprotect),
    ]
    .into_iter()
    .filter(|(_, posture)| matches!(posture, Posture::Unknown { .. }))
    .map(|(name, _)| name)
    .collect()
}
