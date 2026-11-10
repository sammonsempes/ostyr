//! Second slice of the Suricata mapping: `fileinfo`, `smb`, `krb5`, `dcerpc` and the context an `alert` line carries.

use crate::suricata::{checked, clean, clean_opt, non_empty, raw_field, with_labels, BAD_LABEL_PREFIX};
use crate::types::{Label, RawFields};
use core_export::ecs::{
    DnsFields, DnsQuestion, EcsEvent, EventFields, FileFields, HashFields, TlsClientFields, TlsFields, UrlFields, UserAgentFields, UserFields,
};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;


pub const MD5_CHARS: usize = 32;


pub const SHA1_CHARS: usize = 40;


pub const SHA256_CHARS: usize = 64;


pub const FAILURE: &str = "failure";


#[derive(Debug, Default, Deserialize)]
pub struct Fileinfo {
    pub filename: Option<String>,
    pub state: Option<String>,
    pub stored: Option<Value>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Smb {
    pub command: Option<String>,
    pub dialect: Option<String>,
    pub status: Option<String>,
    pub filename: Option<String>,
    pub share: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Krb5 {
    pub cname: Option<String>,
    pub realm: Option<String>,
    pub sname: Option<String>,
    pub encryption: Option<String>,
    pub error_code: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
pub struct DcerpcRequest {
    pub opnum: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
pub struct DcerpcInterface {
    pub uuid: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Dcerpc {
    pub request: Option<String>,
    pub response: Option<String>,
    pub req: Option<DcerpcRequest>,
    #[serde(default)]
    pub interfaces: Vec<DcerpcInterface>,
}


fn bad_label(name: &str, raw: &str) -> Label {
    warn!(name, "a field of the wrong type is kept as a label");
    (format!("{BAD_LABEL_PREFIX}{name}"), clean(raw))
}


fn text_label(name: &str, text: Option<&String>) -> Option<Label> {
    clean_opt(text).map(|found| (name.to_string(), found))
}


/// The last path component, `/` or `\` separated.
pub fn basename(path: &str) -> &str {
    path.rsplit_once(['/', '\\']).map_or(path, |(_, name)| name)
}


fn hash(field: &str, text: Option<&String>, length: usize) -> (Option<String>, Option<Label>) {
    match text.filter(|found| !found.is_empty()) {
        None => (None, None),
        Some(found) if found.len() == length && found.chars().all(|digit| digit.is_ascii_hexdigit()) => (Some(found.to_lowercase()), None),
        Some(found) => (None, Some(bad_label(&format!("fileinfo_{field}"), found))),
    }
}


/// `fileinfo`: a file seen on the wire; a hash of the wrong length or alphabet is kept as a `suricata_bad_` label.
pub fn fileinfo_event(file: &Fileinfo, fields: &RawFields, base: EcsEvent) -> EcsEvent {
    let (size, bad_size) = checked("fileinfo_size", raw_field(fields, "size"));
    let (md5, bad_md5) = hash("md5", file.md5.as_ref(), MD5_CHARS);
    let (sha1, bad_sha1) = hash("sha1", file.sha1.as_ref(), SHA1_CHARS);
    let (sha256, bad_sha256) = hash("sha256", file.sha256.as_ref(), SHA256_CHARS);
    let stored = file
        .stored
        .as_ref()
        .filter(|found| !found.is_null())
        .map(|found| ("suricata_file_stored".to_string(), clean(&found.to_string())));
    with_labels(
        EcsEvent {
            event: EventFields {
                category: vec!["file".to_string()],
                ..base.event.clone()
            },
            file: non_empty(FileFields {
                path: clean_opt(file.filename.as_ref()),
                name: file.filename.as_deref().map(basename).filter(|name| !name.is_empty()).map(clean),
                size,
                hash: non_empty(HashFields { md5, sha1, sha256 }),
            }),
            ..base
        },
        [
            bad_size,
            bad_md5,
            bad_sha1,
            bad_sha256,
            stored,
            text_label("suricata_file_state", file.state.as_ref()),
        ],
    )
}


/// `smb`: `event.action` is the SMB command, the rest goes to labels.
pub fn smb_event(smb: &Smb, base: EcsEvent) -> EcsEvent {
    with_labels(
        EcsEvent {
            event: EventFields {
                action: clean_opt(smb.command.as_ref()),
                ..base.event.clone()
            },
            ..base
        },
        [
            text_label("suricata_smb_dialect", smb.dialect.as_ref()),
            text_label("suricata_smb_status", smb.status.as_ref()),
            text_label("suricata_smb_filename", smb.filename.as_ref()),
            text_label("suricata_smb_share", smb.share.as_ref()),
        ],
    )
}


/// `krb5`: an authentication event, a failure when the line carries an `error_code`.
pub fn krb5_event(krb5: &Krb5, base: EcsEvent) -> EcsEvent {
    let failed = krb5.error_code.as_ref().is_some_and(|code| !code.is_null());
    with_labels(
        EcsEvent {
            event: EventFields {
                category: vec!["authentication".to_string()],
                types: vec!["protocol".to_string()],
                outcome: failed.then(|| FAILURE.to_string()),
                ..base.event.clone()
            },
            user: non_empty(UserFields {
                name: clean_opt(krb5.cname.as_ref()),
                ..UserFields::default()
            }),
            ..base
        },
        [
            text_label("suricata_krb5_realm", krb5.realm.as_ref()),
            text_label("suricata_krb5_sname", krb5.sname.as_ref()),
            text_label("suricata_krb5_encryption", krb5.encryption.as_ref()),
        ],
    )
}


fn opnum_label(rpc: &Dcerpc) -> Option<Label> {
    match rpc.req.as_ref().and_then(|req| req.opnum.as_ref()) {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) if number.is_u64() => Some(("suricata_dcerpc_opnum".to_string(), number.to_string())),
        Some(other) => Some(bad_label("dcerpc_opnum", &other.to_string())),
    }
}


/// `dcerpc`: `event.action` is the request (else the response) kind; the opnum and the first interface uuid are labels.
pub fn dcerpc_event(rpc: &Dcerpc, base: EcsEvent) -> EcsEvent {
    let uuid = rpc.interfaces.first().and_then(|interface| interface.uuid.as_ref());
    with_labels(
        EcsEvent {
            event: EventFields {
                action: clean_opt(rpc.request.as_ref().or(rpc.response.as_ref())),
                ..base.event.clone()
            },
            ..base
        },
        [opnum_label(rpc), text_label("suricata_dcerpc_interface_uuid", uuid)],
    )
}


fn context_text(value: &Value, object: &str, key: &str) -> (Option<String>, Option<Label>) {
    match value.get(object) {
        None | Some(Value::Null) => (None, None),
        Some(Value::Object(fields)) => match fields.get(key) {
            None | Some(Value::Null) => (None, None),
            Some(Value::String(text)) => (Some(clean(text)).filter(|found| !found.is_empty()), None),
            Some(other) => (None, Some(bad_label(&format!("alert_{object}_{key}"), &other.to_string()))),
        },
        Some(other) => (None, Some(bad_label(&format!("alert_{object}"), &other.to_string()))),
    }
}


/// The metadata objects of an `alert` line, read leniently: a field of the wrong type is dropped and kept as a `suricata_bad_alert_` label.
pub fn alert_context(value: &Value, event: EcsEvent) -> EcsEvent {
    let (domain, bad_domain) = context_text(value, "http", "hostname");
    let (original, bad_url) = context_text(value, "http", "url");
    let (agent, bad_agent) = context_text(value, "http", "http_user_agent");
    let (server_name, bad_sni) = context_text(value, "tls", "sni");
    let (question, bad_question) = context_text(value, "dns", "rrname");
    with_labels(
        EcsEvent {
            url: non_empty(UrlFields {
                domain,
                path: None,
                original,
            }),
            user_agent: non_empty(UserAgentFields { original: agent }),
            tls: non_empty(TlsFields {
                client: non_empty(TlsClientFields { server_name, ja3: None }),
                ..TlsFields::default()
            }),
            dns: non_empty(DnsFields {
                question: DnsQuestion { name: question, kind: None },
                ..DnsFields::default()
            }),
            ..event
        },
        [bad_domain, bad_url, bad_agent, bad_sni, bad_question],
    )
}
