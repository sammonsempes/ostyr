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


/// Keeps the first `MAX_AUDIT_CHARS` characters and appends the omitted count, so a cut is always visible.
pub fn cut(text: &str) -> String {
    let total = text.chars().count();
    let kept: String = text.chars().take(MAX_AUDIT_CHARS).collect();
    match total > MAX_AUDIT_CHARS {
        true => format!("{kept}...[+{} chars]", total - MAX_AUDIT_CHARS),
        false => kept,
    }
}


/// Request fields, the decision and the approvers only: the MFA proof and every token stay out.
pub fn open_audit(request: &OpenRequest, decision: &OpenDecision) -> AuditFields {
    let (decision_name, refusal, approvers) = match decision {
        OpenDecision::Allowed { approved_by, .. } => (DECISION_ALLOWED, None, approved_by.iter().map(|subject| cut(subject)).collect()),
        OpenDecision::Refused(reason) => (DECISION_REFUSED, Some(reason.to_string()), Vec::new()),
    };
    AuditFields {
        request_id: cut(&request.request_id),
        tenant: cut(&request.tenant),
        requester: cut(&request.requester),
        asset: cut(&request.asset),
        ticket: cut(&request.ticket),
        decision: decision_name,
        refusal,
        approvers,
    }
}
