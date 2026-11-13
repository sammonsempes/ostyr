mod common;


use common::types::TestResult;
use remote_shell::audit::{escape_cut, open_audit, DECISION_ALLOWED, DECISION_REFUSED, MAX_AUDIT_CHARS};
use remote_shell::open::{OpenDecision, OpenRefusal, OpenRequest};


const EXTRA: usize = 5;


const HUGE: usize = 10_000;


const FORGED_OMITTED: usize = 9;


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
fn escape_cut_keeps_short_text_and_marks_a_cut_visibly() -> TestResult {
    let exact = "a".repeat(MAX_AUDIT_CHARS);
    assert_eq!(escape_cut(&exact), exact);
    let long = "a".repeat(MAX_AUDIT_CHARS + EXTRA);
    assert_eq!(escape_cut(&long), format!("{}...[+{EXTRA} chars]", "a".repeat(MAX_AUDIT_CHARS)));
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


#[test]
fn hostile_characters_are_escaped_in_a_refused_audit() -> TestResult {
    let hostile = OpenRequest {
        requester: "al\nice\u{202e}\u{3164}".to_string(),
        asset: "a\r\u{2028}b".to_string(),
        ..request()
    };
    let fields = open_audit(&hostile, &OpenDecision::Refused(OpenRefusal::Requester));
    assert_eq!(fields.requester, "al\\u{a}ice\\u{202e}\\u{3164}");
    assert_eq!(fields.asset, "a\\u{d}\\u{2028}b");
    Ok(())
}


#[test]
fn a_huge_hostile_field_holds_only_graphic_text_and_is_cut_whole_escapes() -> TestResult {
    let hostile = OpenRequest {
        ticket: "\u{3164}".repeat(HUGE),
        requester: "\n".repeat(HUGE),
        ..request()
    };
    let fields = open_audit(&hostile, &OpenDecision::Refused(OpenRefusal::Ticket));
    assert!(fields.ticket.chars().all(|character| character.is_ascii_graphic() || character == ' '));
    assert!(fields.ticket.contains("...[+"));
    let (body, _) = fields.ticket.split_once("...[").ok_or("no cut marker")?;
    assert!(body.len() <= MAX_AUDIT_CHARS);
    assert!(body.ends_with("\\u{3164}"));
    assert!(fields.requester.starts_with("\\u{a}\\u{a}"));
    Ok(())
}


#[test]
fn approvers_are_escaped_too() -> TestResult {
    let decision = OpenDecision::Allowed {
        idle_timeout: 1,
        max_duration: 1,
        approved_by: vec!["bo\u{202e}b".to_string()],
    };
    assert_eq!(open_audit(&request(), &decision).approvers, vec!["bo\\u{202e}b".to_string()]);
    Ok(())
}


#[test]
fn a_literal_backslash_text_differs_from_the_real_control_character() -> TestResult {
    let refused = OpenDecision::Refused(OpenRefusal::Requester);
    let literal = open_audit(
        &OpenRequest {
            requester: "a\\u{a}b".to_string(),
            ..request()
        },
        &refused,
    );
    let real = open_audit(
        &OpenRequest {
            requester: "a\nb".to_string(),
            ..request()
        },
        &refused,
    );
    assert_ne!(literal.requester, real.requester);
    assert_eq!(literal.requester, "a\\u{5c}u{a}b");
    assert_eq!(real.requester, "a\\u{a}b");
    Ok(())
}


#[test]
fn a_forged_cut_marker_differs_from_a_real_cut() -> TestResult {
    let forged = escape_cut(&format!("{}...[+9 chars]", "a".repeat(MAX_AUDIT_CHARS + EXTRA)));
    let real = escape_cut(&"a".repeat(MAX_AUDIT_CHARS + FORGED_OMITTED));
    assert_ne!(forged, real);
    assert!(forged.ends_with("...[+18 chars]"));
    assert!(real.ends_with("...[+9 chars]"));
    assert_eq!(escape_cut("a\\"), "a\\u{5c}");
    Ok(())
}
