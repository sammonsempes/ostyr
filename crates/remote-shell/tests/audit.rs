mod common;


use common::types::TestResult;
use remote_shell::audit::{cut, open_audit, DECISION_ALLOWED, DECISION_REFUSED, MAX_AUDIT_CHARS};
use remote_shell::open::{OpenDecision, OpenRefusal, OpenRequest};


const EXTRA: usize = 5;


const CREATED_AT: i64 = 1_800_000_000;


fn request() -> OpenRequest {
    OpenRequest {
        request_id: "req-1".to_string(),
        tenant: "acme".to_string(),
        requester: "alice".to_string(),
        asset: "host-7".to_string(),
        ticket: "INC-1".to_string(),
        created_at: CREATED_AT,
    }
}


#[test]
fn an_allowed_decision_lists_the_approvers() -> TestResult {
    let decision = OpenDecision::Allowed {
        idle_timeout: 1,
        max_duration: 1,
        approved_by: vec!["bob".to_string()],
    };
    let fields = open_audit(&request(), &decision);
    assert_eq!(fields.decision, DECISION_ALLOWED);
    assert_eq!(fields.refusal, None);
    assert_eq!(fields.approvers, vec!["bob".to_string()]);
    assert_eq!(fields.request_id, "req-1");
    assert_eq!(fields.tenant, "acme");
    assert_eq!(fields.requester, "alice");
    assert_eq!(fields.asset, "host-7");
    assert_eq!(fields.ticket, "INC-1");
    Ok(())
}


#[test]
fn a_refused_decision_names_the_reason_and_no_approver() -> TestResult {
    let fields = open_audit(&request(), &OpenDecision::Refused(OpenRefusal::MfaMissing));
    assert_eq!(fields.decision, DECISION_REFUSED);
    assert_eq!(fields.refusal, Some("mfa_missing".to_string()));
    assert!(fields.approvers.is_empty());
    Ok(())
}


#[test]
fn the_audit_holds_no_proof_material() -> TestResult {
    let shown = format!("{:?}", open_audit(&request(), &OpenDecision::Refused(OpenRefusal::MfaExpired)));
    assert!(!shown.contains("verified_at"));
    assert!(!shown.contains("proof"));
    Ok(())
}


#[test]
fn cut_keeps_short_text_and_marks_a_cut_visibly() -> TestResult {
    let exact = "a".repeat(MAX_AUDIT_CHARS);
    assert_eq!(cut(&exact), exact);
    let long = "\u{e9}".repeat(MAX_AUDIT_CHARS + EXTRA);
    assert_eq!(cut(&long), format!("{}...[+{EXTRA} chars]", "\u{e9}".repeat(MAX_AUDIT_CHARS)));
    Ok(())
}


#[test]
fn hostile_request_fields_are_cut_in_the_audit() -> TestResult {
    let hostile = OpenRequest {
        requester: "x".repeat(MAX_AUDIT_CHARS + EXTRA),
        ..request()
    };
    let fields = open_audit(&hostile, &OpenDecision::Refused(OpenRefusal::Requester));
    assert!(fields.requester.ends_with("[+5 chars]"));
    Ok(())
}
