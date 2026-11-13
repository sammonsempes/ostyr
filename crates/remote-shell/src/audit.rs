use crate::open::{OpenDecision, OpenRequest};


pub const MAX_AUDIT_CHARS: usize = 256;


pub const DECISION_ALLOWED: &str = "allowed";


pub const DECISION_REFUSED: &str = "refused";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFields {
    pub request_id: String,
    pub tenant: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub decision: &'static str,
    pub refusal: Option<String>,
    pub approvers: Vec<String>,
}


/// Any character outside ASCII graphic (backslash excluded) and space becomes `\u{hex}`, so the audit never holds a control, bidi or blank character.
pub fn escape_char(character: char) -> String {
    match (character.is_ascii_graphic() && character != '\\') || character == ' ' {
        true => character.to_string(),
        false => format!("\\u{{{:x}}}", u32::from(character)),
    }
}


/// Escapes first, then cuts at `MAX_AUDIT_CHARS` on whole escapes with the visible marker, so a cut never splits an escape.
pub fn escape_cut(text: &str) -> String {
    let units: Vec<String> = text.chars().map(escape_char).collect();
    let total: usize = units.iter().map(|unit| unit.len()).sum();
    let kept: String = units
        .iter()
        .scan(usize::default(), |used, unit| {
            *used += unit.len();
            (*used <= MAX_AUDIT_CHARS).then_some(unit.as_str())
        })
        .collect();
    match total > MAX_AUDIT_CHARS {
        true => format!("{kept}...[+{} chars]", total - kept.len()),
        false => kept,
    }
}


/// Request fields, the decision and the approvers only: the MFA proof and every token stay out.
pub fn open_audit(request: &OpenRequest, decision: &OpenDecision) -> AuditFields {
    let (decision_name, refusal, approvers) = match decision {
        OpenDecision::Allowed { approved_by, .. } => (DECISION_ALLOWED, None, approved_by.iter().map(|subject| escape_cut(subject)).collect()),
        OpenDecision::Refused(reason) => (DECISION_REFUSED, Some(reason.to_string()), Vec::new()),
    };
    AuditFields {
        request_id: escape_cut(&request.request_id),
        tenant: escape_cut(&request.tenant),
        requester: escape_cut(&request.requester),
        asset: escape_cut(&request.asset),
        ticket: escape_cut(&request.ticket),
        decision: decision_name,
        refusal,
        approvers,
    }
}
