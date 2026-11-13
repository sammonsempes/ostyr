mod common;


use cmdb::model::Criticality;
use common::types::TestResult;
use core_auth::types::{RoleCatalog, RoleSet};
use remote_shell::open::{
    age_of, decide_open, Approval, Evidence, MfaProof, OpenDecision, OpenRefusal, OpenRequest, MAX_APPROVALS, MAX_CLOCK_SKEW_SECONDS,
    PERMISSION_REMOTE_SHELL_APPROVE, PERMISSION_REMOTE_SHELL_OPEN,
};
use remote_shell::policy::{validate_policy, ShellPolicy, ValidatedPolicy, DEFAULT_APPROVAL_MAX_AGE_SECONDS, DEFAULT_MFA_MAX_AGE_SECONDS};
use remote_shell::types::Seconds;


const NOW: Seconds = 1_800_000_000;


const CREATED_AGO: Seconds = 60;


const MFA_AGO: Seconds = 30;


const APPROVAL_AGO: Seconds = 10;


const TEN_MINUTES: Seconds = 600;


const LONG_SUBJECT: usize = 256;


const MANY_APPROVALS: usize = 100_000;


fn catalog() -> RoleCatalog {
    [
        ("operator", [PERMISSION_REMOTE_SHELL_OPEN]),
        ("approver", [PERMISSION_REMOTE_SHELL_APPROVE]),
    ]
    .into_iter()
    .map(|(role, permissions)| (role.to_string(), permissions.into_iter().map(str::to_string).collect()))
    .collect()
}


fn roles(names: &[&str]) -> RoleSet {
    names.iter().map(|name| name.to_string()).collect()
}


fn request() -> OpenRequest {
    OpenRequest {
        request_id: "req-1".to_string(),
        tenant: "acme".to_string(),
        requester: "alice".to_string(),
        asset: "host-7".to_string(),
        ticket: "INC-1".to_string(),
        created_at: NOW - CREATED_AGO,
    }
}


fn mfa() -> MfaProof {
    MfaProof {
        request_id: "req-1".to_string(),
        tenant: "acme".to_string(),
        subject: "alice".to_string(),
        verified_at: NOW - MFA_AGO,
    }
}


fn approval(approver: &str) -> Approval {
    Approval {
        request_id: "req-1".to_string(),
        tenant: "acme".to_string(),
        approver: approver.to_string(),
        approved_at: NOW - APPROVAL_AGO,
    }
}


fn evidence(approvals: Vec<Approval>) -> Evidence {
    Evidence {
        mfa: Some(mfa()),
        approvals,
        approver_roles: [("bob", "approver"), ("carol", "approver"), ("alice", "approver"), ("dave", "operator")]
            .into_iter()
            .map(|(subject, role)| (subject.to_string(), roles(&[role])))
            .collect(),
    }
}


fn decide(request: &OpenRequest, criticality: Option<Criticality>, evidence: &Evidence) -> OpenDecision {
    decide_open(
        &ValidatedPolicy::default(),
        &catalog(),
        request,
        &roles(&["operator"]),
        criticality,
        evidence,
        NOW,
    )
}


fn refused(reason: OpenRefusal) -> OpenDecision {
    OpenDecision::Refused(reason)
}


fn critical_with(approvals: Vec<Approval>) -> OpenDecision {
    decide(&request(), Some(Criticality::Critical), &evidence(approvals))
}


#[test]
fn a_medium_asset_with_role_ticket_and_fresh_mfa_is_allowed() -> TestResult {
    let policy = ShellPolicy::default();
    assert_eq!(
        decide(&request(), Some(Criticality::Medium), &evidence(Vec::new())),
        OpenDecision::Allowed {
            idle_timeout: policy.idle_timeout_seconds,
            max_duration: policy.max_duration_seconds,
            approved_by: Vec::new()
        }
    );
    Ok(())
}


#[test]
fn an_invalid_tenant_is_refused() -> TestResult {
    let other = OpenRequest {
        tenant: "-x".to_string(),
        ..request()
    };
    assert_eq!(
        decide(&other, Some(Criticality::Low), &evidence(Vec::new())),
        refused(OpenRefusal::Tenant)
    );
    Ok(())
}


#[test]
fn an_invalid_requester_is_refused() -> TestResult {
    let other = OpenRequest {
        requester: "alice ".to_string(),
        ..request()
    };
    assert_eq!(
        decide(&other, Some(Criticality::Low), &evidence(Vec::new())),
        refused(OpenRefusal::Requester)
    );
    Ok(())
}


#[test]
fn an_invalid_request_id_is_refused_even_when_the_proof_carries_the_same_one() -> TestResult {
    let other = OpenRequest {
        request_id: String::new(),
        ..request()
    };
    let matching = Evidence {
        mfa: Some(MfaProof {
            request_id: String::new(),
            tenant: "acme".to_string(),
            subject: "alice".to_string(),
            verified_at: NOW - MFA_AGO,
        }),
        ..evidence(Vec::new())
    };
    assert_eq!(decide(&other, Some(Criticality::Low), &matching), refused(OpenRefusal::RequestId));
    Ok(())
}


#[test]
fn a_requester_without_the_role_is_refused() -> TestResult {
    let decision = decide_open(
        &ValidatedPolicy::default(),
        &catalog(),
        &request(),
        &roles(&["approver", "unknown"]),
        Some(Criticality::Low),
        &evidence(Vec::new()),
        NOW,
    );
    assert_eq!(decision, refused(OpenRefusal::Role));
    Ok(())
}


#[test]
fn a_missing_or_malformed_ticket_is_refused() -> TestResult {
    let no_ticket = OpenRequest {
        ticket: String::new(),
        ..request()
    };
    let dash_ticket = OpenRequest {
        ticket: "-INC".to_string(),
        ..request()
    };
    assert_eq!(
        decide(&no_ticket, Some(Criticality::Low), &evidence(Vec::new())),
        refused(OpenRefusal::Ticket)
    );
    assert_eq!(
        decide(&dash_ticket, Some(Criticality::Low), &evidence(Vec::new())),
        refused(OpenRefusal::Ticket)
    );
    Ok(())
}


#[test]
fn a_missing_mfa_proof_is_refused() -> TestResult {
    let no_proof = Evidence {
        mfa: None,
        ..evidence(Vec::new())
    };
    assert_eq!(decide(&request(), Some(Criticality::Low), &no_proof), refused(OpenRefusal::MfaMissing));
    Ok(())
}


#[test]
fn a_proof_issued_for_another_request_is_refused() -> TestResult {
    let replayed = Evidence {
        mfa: Some(MfaProof {
            request_id: "req-0".to_string(),
            tenant: "acme".to_string(),
            subject: "alice".to_string(),
            verified_at: NOW - MFA_AGO,
        }),
        ..evidence(Vec::new())
    };
    assert_eq!(
        decide(&request(), Some(Criticality::Low), &replayed),
        refused(OpenRefusal::MfaOtherRequest)
    );
    Ok(())
}


#[test]
fn a_proof_from_the_future_is_refused() -> TestResult {
    let ahead = Evidence {
        mfa: Some(MfaProof {
            request_id: "req-1".to_string(),
            tenant: "acme".to_string(),
            subject: "alice".to_string(),
            verified_at: NOW + TEN_MINUTES,
        }),
        ..evidence(Vec::new())
    };
    assert_eq!(decide(&request(), Some(Criticality::Low), &ahead), refused(OpenRefusal::MfaNotFresh));
    Ok(())
}


#[test]
fn a_proof_older_than_the_request_is_refused_and_one_at_its_creation_is_accepted() -> TestResult {
    let proof_at = |verified_at| Evidence {
        mfa: Some(MfaProof {
            request_id: "req-1".to_string(),
            tenant: "acme".to_string(),
            subject: "alice".to_string(),
            verified_at,
        }),
        ..evidence(Vec::new())
    };
    let created_at = request().created_at;
    assert_eq!(
        decide(&request(), Some(Criticality::Low), &proof_at(created_at - 1)),
        refused(OpenRefusal::MfaNotFresh)
    );
    assert!(matches!(
        decide(&request(), Some(Criticality::Low), &proof_at(created_at)),
        OpenDecision::Allowed { .. }
    ));
    Ok(())
}


#[test]
fn a_proof_is_valid_up_to_the_maximum_age_and_expired_after() -> TestResult {
    let max_age = Seconds::try_from(DEFAULT_MFA_MAX_AGE_SECONDS)?;
    let aged = |age| Evidence {
        mfa: Some(MfaProof {
            request_id: "req-1".to_string(),
            tenant: "acme".to_string(),
            subject: "alice".to_string(),
            verified_at: NOW - age,
        }),
        ..evidence(Vec::new())
    };
    let early = OpenRequest {
        created_at: NOW - max_age - CREATED_AGO,
        ..request()
    };
    assert!(matches!(
        decide(&early, Some(Criticality::Low), &aged(max_age)),
        OpenDecision::Allowed { .. }
    ));
    assert_eq!(
        decide(&early, Some(Criticality::Low), &aged(max_age + 1)),
        refused(OpenRefusal::MfaExpired)
    );
    Ok(())
}


#[test]
fn a_critical_asset_without_approval_is_refused() -> TestResult {
    assert_eq!(critical_with(Vec::new()), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn a_critical_asset_with_a_second_approver_is_allowed() -> TestResult {
    let policy = ShellPolicy::default();
    assert_eq!(
        critical_with(vec![approval("bob")]),
        OpenDecision::Allowed {
            idle_timeout: policy.idle_timeout_seconds,
            max_duration: policy.max_duration_seconds,
            approved_by: vec!["bob".to_string()]
        }
    );
    Ok(())
}


#[test]
fn an_invalid_approval_is_skipped_for_a_valid_one() -> TestResult {
    assert_eq!(
        critical_with(vec![approval("alice"), approval("bob")]),
        OpenDecision::Allowed {
            idle_timeout: ShellPolicy::default().idle_timeout_seconds,
            max_duration: ShellPolicy::default().max_duration_seconds,
            approved_by: vec!["bob".to_string()]
        }
    );
    Ok(())
}


#[test]
fn an_unknown_asset_is_treated_as_critical() -> TestResult {
    assert_eq!(decide(&request(), None, &evidence(Vec::new())), refused(OpenRefusal::ApprovalRequired));
    assert!(matches!(
        decide(&request(), None, &evidence(vec![approval("bob")])),
        OpenDecision::Allowed { .. }
    ));
    Ok(())
}


#[test]
fn self_approval_is_refused() -> TestResult {
    assert_eq!(critical_with(vec![approval("alice")]), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn approver_subjects_with_whitespace_or_hidden_characters_are_refused() -> TestResult {
    let look_alike = |subject: &str| {
        let mut shown = evidence(vec![approval(subject)]);
        shown.approver_roles.insert(subject.to_string(), roles(&["approver"]));
        decide(&request(), Some(Criticality::Critical), &shown)
    };
    assert_eq!(look_alike("alice "), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(look_alike("alice\u{200b}"), refused(OpenRefusal::ApprovalRequired));
    [
        "alice\u{3164}",
        "alice\u{115f}",
        "alice\u{1160}",
        "alice\u{ffa0}",
        "\u{3164}",
        "alice\u{0345}",
        "al\u{0456}ce",
    ]
    .iter()
    .for_each(|subject| assert_eq!(look_alike(subject), refused(OpenRefusal::ApprovalRequired)));
    assert_eq!(look_alike(""), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(look_alike(&"b".repeat(LONG_SUBJECT)), refused(OpenRefusal::ApprovalRequired));
    assert!(matches!(look_alike("bob"), OpenDecision::Allowed { .. }));
    Ok(())
}


#[test]
fn an_approval_for_another_request_or_tenant_is_refused() -> TestResult {
    let other_request = Approval {
        request_id: "req-2".to_string(),
        ..approval("bob")
    };
    let other_tenant = Approval {
        tenant: "globex".to_string(),
        ..approval("bob")
    };
    assert_eq!(critical_with(vec![other_request]), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(critical_with(vec![other_tenant]), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn an_approver_who_lost_the_role_or_is_unknown_is_refused() -> TestResult {
    assert_eq!(critical_with(vec![approval("dave")]), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(critical_with(vec![approval("erin")]), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn an_approval_is_valid_up_to_the_maximum_age_and_expired_after() -> TestResult {
    let max_age = Seconds::try_from(DEFAULT_APPROVAL_MAX_AGE_SECONDS)?;
    let aged = |age| Approval {
        approved_at: NOW - age,
        ..approval("bob")
    };
    let early = OpenRequest {
        created_at: NOW - max_age - CREATED_AGO,
        ..request()
    };
    let run = |approval| decide(&early, Some(Criticality::Critical), &evidence(vec![approval]));
    assert!(matches!(run(aged(max_age)), OpenDecision::Allowed { .. }));
    assert_eq!(run(aged(max_age + 1)), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn an_approval_from_the_future_is_refused() -> TestResult {
    let at = |approved_at| Approval {
        approved_at,
        ..approval("bob")
    };
    assert!(matches!(
        critical_with(vec![at(NOW + MAX_CLOCK_SKEW_SECONDS)]),
        OpenDecision::Allowed { .. }
    ));
    assert_eq!(
        critical_with(vec![at(NOW + MAX_CLOCK_SKEW_SECONDS + 1)]),
        refused(OpenRefusal::ApprovalRequired)
    );
    assert_eq!(critical_with(vec![at(i64::MAX)]), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(critical_with(vec![at(i64::MIN)]), refused(OpenRefusal::ApprovalRequired));
    Ok(())
}


#[test]
fn too_many_approvals_are_refused_before_any_is_read() -> TestResult {
    let valid_then_flood = (0..MANY_APPROVALS).map(|_| approval("bob")).collect::<Vec<_>>();
    assert_eq!(critical_with(valid_then_flood.clone()), refused(OpenRefusal::TooManyApprovals));
    assert_eq!(
        decide(&request(), Some(Criticality::Low), &evidence(valid_then_flood)),
        refused(OpenRefusal::TooManyApprovals)
    );
    let at_the_cap = (0..MAX_APPROVALS).map(|_| approval("bob")).collect::<Vec<_>>();
    assert!(matches!(critical_with(at_the_cap), OpenDecision::Allowed { .. }));
    let over_the_cap = (0..=MAX_APPROVALS).map(|_| approval("bob")).collect::<Vec<_>>();
    assert_eq!(critical_with(over_the_cap), refused(OpenRefusal::TooManyApprovals));
    Ok(())
}


#[test]
fn the_policy_may_lower_the_dual_approval_threshold() -> TestResult {
    let strict = ShellPolicy {
        dual_approval_from: Criticality::High,
        ..ShellPolicy::default()
    };
    let checked = validate_policy(&strict, "strict")?;
    let decide_with = |criticality| {
        decide_open(
            &checked,
            &catalog(),
            &request(),
            &roles(&["operator"]),
            Some(criticality),
            &evidence(Vec::new()),
            NOW,
        )
    };
    assert_eq!(decide_with(Criticality::High), refused(OpenRefusal::ApprovalRequired));
    assert_eq!(decide_with(Criticality::Critical), refused(OpenRefusal::ApprovalRequired));
    assert!(matches!(decide_with(Criticality::Medium), OpenDecision::Allowed { .. }));
    Ok(())
}


#[test]
fn the_first_failing_check_is_the_one_reported() -> TestResult {
    let broken = OpenRequest {
        request_id: String::new(),
        tenant: "-x".to_string(),
        requester: " ".to_string(),
        asset: "host-7".to_string(),
        ticket: String::new(),
        created_at: NOW,
    };
    let none = Evidence {
        mfa: None,
        ..evidence(Vec::new())
    };
    let run =
        |request: &OpenRequest, roles_held: &RoleSet| decide_open(&ValidatedPolicy::default(), &catalog(), request, roles_held, None, &none, NOW);
    let no_roles = RoleSet::new();
    assert_eq!(run(&broken, &no_roles), refused(OpenRefusal::Tenant));
    let tenant_fixed = OpenRequest {
        tenant: "acme".to_string(),
        ..broken
    };
    assert_eq!(run(&tenant_fixed, &no_roles), refused(OpenRefusal::Requester));
    let requester_fixed = OpenRequest {
        requester: "alice".to_string(),
        ..tenant_fixed
    };
    assert_eq!(run(&requester_fixed, &no_roles), refused(OpenRefusal::RequestId));
    let id_fixed = OpenRequest {
        request_id: "req-1".to_string(),
        ..requester_fixed
    };
    assert_eq!(run(&id_fixed, &no_roles), refused(OpenRefusal::Role));
    assert_eq!(run(&id_fixed, &roles(&["operator"])), refused(OpenRefusal::Ticket));
    let ticket_fixed = OpenRequest {
        ticket: "INC-1".to_string(),
        ..id_fixed
    };
    assert_eq!(run(&ticket_fixed, &roles(&["operator"])), refused(OpenRefusal::MfaMissing));
    Ok(())
}


#[test]
fn age_of_refuses_the_future_and_overflow() -> TestResult {
    assert_eq!(age_of(NOW - 1, NOW), Some(1));
    assert_eq!(age_of(NOW + MAX_CLOCK_SKEW_SECONDS, NOW), Some(0));
    assert_eq!(age_of(NOW + MAX_CLOCK_SKEW_SECONDS + 1, NOW), None);
    assert_eq!(age_of(0, i64::MAX), None);
    assert_eq!(age_of(i64::MIN, NOW), None);
    Ok(())
}


#[test]
fn an_approval_dated_before_the_request_is_refused() -> TestResult {
    let at = |approved_at| Approval {
        approved_at,
        ..approval("bob")
    };
    let created_at = request().created_at;
    assert_eq!(critical_with(vec![at(created_at - 1)]), refused(OpenRefusal::ApprovalRequired));
    assert!(matches!(critical_with(vec![at(created_at)]), OpenDecision::Allowed { .. }));
    Ok(())
}


#[test]
fn a_proof_for_another_tenant_or_subject_is_refused() -> TestResult {
    let with = |tenant: &str, subject: &str| Evidence {
        mfa: Some(MfaProof {
            request_id: "req-1".to_string(),
            tenant: tenant.to_string(),
            subject: subject.to_string(),
            verified_at: NOW - MFA_AGO,
        }),
        ..evidence(Vec::new())
    };
    assert_eq!(
        decide(&request(), Some(Criticality::Low), &with("globex", "alice")),
        refused(OpenRefusal::MfaOtherTenant)
    );
    assert_eq!(
        decide(&request(), Some(Criticality::Low), &with("acme", "bob")),
        refused(OpenRefusal::MfaOtherSubject)
    );
    assert!(matches!(
        decide(&request(), Some(Criticality::Low), &with("acme", "alice")),
        OpenDecision::Allowed { .. }
    ));
    Ok(())
}


#[test]
fn an_asset_outside_the_reference_grammar_is_refused() -> TestResult {
    let on = |asset: &str| {
        let other = OpenRequest {
            asset: asset.to_string(),
            ..request()
        };
        decide(&other, Some(Criticality::Low), &evidence(Vec::new()))
    };
    assert_eq!(on("host\n7"), refused(OpenRefusal::Asset));
    assert_eq!(on("host\u{202e}7"), refused(OpenRefusal::Asset));
    assert_eq!(on(""), refused(OpenRefusal::Asset));
    assert!(matches!(on("host-7"), OpenDecision::Allowed { .. }));
    Ok(())
}
