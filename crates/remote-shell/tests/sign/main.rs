#[path = "../common/types.rs"]
mod common_types;
mod fake;


use agent_channel::model::{GateError, Identity, ShellGate};
use agent_channel::shell_gate::{gate_add, gate_has_pending, lock_gate, new_gate};
use agent_command::codec::decode_exact;
use agent_command::model::{Action, Command, Envelope, KeyClass, TrustedKey, EXCLUSIVE_ACTIONS};
use agent_command::sign::{memory_signer, os_random};
use agent_command::types::{BoxError, FillFn, SignerFn};
use agent_command::verify::{check_scope, check_signature};
use cmdb::model::Criticality;
use common_types::TestResult;
use core_auth::types::{RoleCatalog, RoleSet};
use core_pg::scope::{tenant_scope, TenantScope};
use ed25519_dalek::SigningKey;
use fake::{handle, Db, Edit, Signed, Stored};
use remote_shell::agent_map::AgentMap;
use remote_shell::error::{SignError, StoreError};
use remote_shell::open::{Approval, Evidence, MfaProof, OpenRefusal, PERMISSION_REMOTE_SHELL_APPROVE, PERMISSION_REMOTE_SHELL_OPEN};
use remote_shell::policy::ValidatedPolicy;
use remote_shell::sign::{
    sign_open_shell, CLAIM_SQL, MAX_PENDING_SHELLS_PER_TENANT, MAX_SIGN_DELAY_SECONDS, SEQUENCE_SQL, SIGN_LIFETIME_SECONDS, SIGN_STATE_SQL,
};
use remote_shell::sign_model::{SignInputs, SignedShell, Signing};
use remote_shell::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use remote_shell::store_model::{SessionRow, Statement};
use remote_shell::types::{BoxedCause, Seconds};
use std::cell::{Cell as Counter, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;


const NOW: Seconds = 1_800_000_000;


const OPENED_AGO: Seconds = 30;


const MFA_AGO: Seconds = 10;


const SEED: u8 = 7;


const KEY_BYTES: usize = 32;


const CLOCK_MARGIN: i64 = 10;


const STATE_SCOPED_TWICE: usize = 2;


const TENANT_CAP: usize = 16;


const MAX_SECONDS_DEFAULT: u32 = 14_400;


const IDLE_SECONDS_DEFAULT: u32 = 900;


const FIRST_SEQUENCE: u64 = 1;


const FIXED_SEQUENCE: u64 = 77;


const FIXED_SEQUENCE_STORED: i64 = 77;


const STATE_COLUMNS: usize = 7;


const UNREADABLE_COLUMNS: [usize; 6] = [0, 1, 2, 3, 4, 6];


const REQUIRED_COLUMNS: [usize; 5] = [1, 2, 3, 4, 6];


const MARKER: &str = "MARKERVALUE";


const SESSION: &str = "sess-1";


const ACME: &str = "acme";


const GLOBEX: &str = "globex";


#[derive(Clone, Copy)]
enum SequencePlan {
    Counter,
    Fixed(u64),
    Fail,
}


struct Setup {
    db: RefCell<Db>,
    gate: Arc<ShellGate>,
    agents: AgentMap,
    scope: TenantScope,
    policy: ValidatedPolicy,
    catalog: RoleCatalog,
    roles: RoleSet,
    evidence: Evidence,
    criticality: Option<Criticality>,
    signer: Box<SignerFn>,
    fill: FillFn,
    plan: SequencePlan,
    counter: Counter<u64>,
    allocations: RefCell<Vec<(String, KeyClass)>>,
}


fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[SEED; KEY_BYTES])
}


fn trusted_key() -> TrustedKey {
    TrustedKey {
        class: KeyClass::Sensitive,
        public_key: signing_key().verifying_key(),
        not_before: 0,
        not_after: u64::MAX,
        revoked: false,
        actions: Some(BTreeSet::from(["open_shell".to_owned()])),
    }
}


fn catalog() -> RoleCatalog {
    [("operator", PERMISSION_REMOTE_SHELL_OPEN), ("approver", PERMISSION_REMOTE_SHELL_APPROVE)]
        .into_iter()
        .map(|(role, permission)| (role.to_owned(), [permission.to_owned()].into_iter().collect()))
        .collect()
}


fn roles(names: &[&str]) -> RoleSet {
    names.iter().map(|name| (*name).to_owned()).collect()
}


fn evidence_at(now: Seconds) -> Evidence {
    Evidence {
        mfa: Some(MfaProof {
            request_id: SESSION.to_owned(),
            tenant: ACME.to_owned(),
            subject: "alice".to_owned(),
            verified_at: now - MFA_AGO,
        }),
        approvals: Vec::new(),
        approver_roles: BTreeMap::new(),
    }
}


fn row_at(now: Seconds) -> SessionRow {
    SessionRow {
        session_id: SESSION.to_owned(),
        requester: "alice".to_owned(),
        asset: "host-7".to_owned(),
        ticket: "INC-1".to_owned(),
        opened_at: now - OPENED_AGO,
        closed_at: None,
        close_reason: None,
        recording_frames: None,
        recording_hash: None,
        recording_bytes: None,
    }
}


fn agent_map(tenant: &str, agent: &str) -> AgentMap {
    AgentMap {
        tenant: tenant.to_owned(),
        agents: BTreeMap::from([("host-7".to_owned(), agent.to_owned())]),
    }
}


fn failing_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn setup() -> Result<Setup, Box<dyn Error>> {
    let setup = Setup {
        db: RefCell::new(Db::default()),
        gate: new_gate(Box::new(|| NOW.unsigned_abs())),
        agents: agent_map(ACME, "agent-a"),
        scope: tenant_scope(ACME)?,
        policy: ValidatedPolicy::default(),
        catalog: catalog(),
        roles: roles(&["operator"]),
        evidence: evidence_at(NOW),
        criticality: Some(Criticality::Low),
        signer: memory_signer(signing_key()),
        fill: os_random,
        plan: SequencePlan::Counter,
        counter: Counter::new(0),
        allocations: RefCell::new(Vec::new()),
    };
    seed(&setup, &row_at(NOW));
    Ok(setup)
}


fn seed(setup: &Setup, row: &SessionRow) {
    setup.db.borrow_mut().sessions.push(Stored {
        tenant: ACME.to_owned(),
        row: row.clone(),
    });
}


async fn attempt(setup: &Setup, row: &SessionRow, now: Seconds) -> Result<SignedShell, SignError> {
    let mut exec = |scope: &TenantScope, statement: Statement| handle(&setup.db, scope, statement);
    let mut allocate = |agent: &str, class: KeyClass| -> Result<u64, BoxedCause> {
        setup.allocations.borrow_mut().push((agent.to_owned(), class));
        match setup.plan {
            SequencePlan::Fixed(value) => Ok(value),
            SequencePlan::Fail => Err("allocator down".into()),
            SequencePlan::Counter => {
                let next = setup.counter.get() + 1;
                setup.counter.set(next);
                Ok(next)
            }
        }
    };
    let inputs = SignInputs {
        policy: &setup.policy,
        catalog: &setup.catalog,
        requester_roles: &setup.roles,
        criticality: setup.criticality,
        evidence: &setup.evidence,
    };
    let mut signing = Signing {
        key_id: "shell-key",
        next_sequence: &mut allocate,
        fill: setup.fill,
        signer: &*setup.signer,
        gate: &setup.gate,
    };
    sign_open_shell(&mut exec, &setup.scope, row, &inputs, &setup.agents, &mut signing, now).await
}


fn nothing_happened(setup: &Setup) -> bool {
    setup.db.borrow().statements.is_empty()
        && setup.db.borrow().signed.is_empty()
        && lock_gate(&setup.gate).pending.is_empty()
        && setup.allocations.borrow().is_empty()
}


fn identity(agent: &str) -> Identity {
    Identity {
        tenant: ACME.to_owned(),
        agent_id: agent.to_owned(),
    }
}


fn decoded(signed: &SignedShell) -> Result<(Envelope, Command), Box<dyn Error>> {
    let envelope: Envelope = decode_exact(&signed.envelope)?;
    let command: Command = decode_exact(&envelope.command)?;
    Ok((envelope, command))
}


#[tokio::test]
async fn a_signed_shell_verifies_and_matches_the_row_the_record_and_the_gate() -> TestResult {
    let setup = setup()?;
    let signed = attempt(&setup, &row_at(NOW), NOW).await?;
    let (envelope, command) = decoded(&signed)?;
    check_signature(&trusted_key(), &envelope)?;
    check_scope(&trusted_key(), &command.action, EXCLUSIVE_ACTIONS)?;
    assert_eq!(signed.identity, identity("agent-a"));
    assert_eq!(envelope.key_id, "shell-key");
    assert_eq!(command.key_id, "shell-key");
    assert_eq!(command.key_class, KeyClass::Sensitive);
    assert_eq!(command.agent_id, "agent-a");
    assert_eq!(command.tenant, ACME);
    assert_eq!(command.issued_at, NOW.unsigned_abs());
    assert_eq!(command.expires_at, NOW.unsigned_abs() + SIGN_LIFETIME_SECONDS.unsigned_abs());
    assert_eq!(command.sequence, FIRST_SEQUENCE);
    assert_eq!(
        command.action,
        Action::OpenShell {
            session_id: SESSION.to_owned(),
            asset: "host-7".to_owned(),
            ticket: "INC-1".to_owned(),
            requester: "alice".to_owned(),
            approvers: Vec::new(),
            max_seconds: MAX_SECONDS_DEFAULT,
            idle_seconds: IDLE_SECONDS_DEFAULT,
        }
    );
    assert_eq!(*setup.allocations.borrow(), vec![("agent-a".to_owned(), KeyClass::Sensitive)]);
    let db = setup.db.borrow();
    let recorded: Vec<&Signed> = db.signed.iter().collect();
    assert_eq!(recorded.len(), 1);
    assert!(recorded.iter().all(|entry| entry.agent_id == "agent-a"
        && entry.key_id == "shell-key"
        && entry.approvers.is_empty()
        && entry.max_seconds == i64::from(MAX_SECONDS_DEFAULT)
        && entry.idle_seconds == i64::from(IDLE_SECONDS_DEFAULT)
        && entry.issued_at == NOW
        && entry.expires_at == NOW + SIGN_LIFETIME_SECONDS
        && entry.sequence == Some(1)));
    assert!(gate_has_pending(&setup.gate, &identity("agent-a")));
    assert_eq!(db.statements, vec![CLAIM_SQL, SEQUENCE_SQL]);
    Ok(())
}


#[tokio::test]
async fn the_approver_comes_from_the_recomputed_decision() -> TestResult {
    let mut setup = setup()?;
    setup.criticality = Some(Criticality::Critical);
    setup.evidence.approvals = vec![Approval {
        request_id: SESSION.to_owned(),
        tenant: ACME.to_owned(),
        approver: "bob".to_owned(),
        approved_at: NOW - MFA_AGO,
    }];
    setup.evidence.approver_roles = BTreeMap::from([("bob".to_owned(), roles(&["approver"]))]);
    let signed = attempt(&setup, &row_at(NOW), NOW).await?;
    let (_, command) = decoded(&signed)?;
    assert!(matches!(command.action, Action::OpenShell { ref approvers, .. } if *approvers == vec!["bob".to_owned()]));
    assert!(setup.db.borrow().signed.iter().all(|entry| entry.approvers == "bob"));
    Ok(())
}


#[tokio::test]
async fn a_denied_decision_signs_nothing() -> TestResult {
    let mut setup = setup()?;
    setup.evidence.mfa = None;
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::MfaMissing))
    ));
    setup.criticality = Some(Criticality::Critical);
    setup.evidence = evidence_at(NOW);
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::ApprovalRequired))
    ));
    setup.criticality = None;
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::ApprovalRequired))
    ));
    setup.roles = roles(&[]);
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::Role))
    ));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn a_decision_is_recomputed_for_this_row_never_for_another() -> TestResult {
    let mut setup = setup()?;
    setup.evidence.mfa = Some(MfaProof {
        request_id: "other-session".to_owned(),
        tenant: ACME.to_owned(),
        subject: "alice".to_owned(),
        verified_at: NOW - MFA_AGO,
    });
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::MfaOtherRequest))
    ));
    setup.evidence = evidence_at(NOW);
    setup.evidence.mfa = setup.evidence.mfa.map(|proof| MfaProof {
        subject: "mallory".to_owned(),
        ..proof
    });
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Refused(OpenRefusal::MfaOtherSubject))
    ));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn a_closed_row_and_a_row_closed_after_the_read_are_refused() -> TestResult {
    let setup = setup()?;
    let closed = SessionRow {
        closed_at: Some(NOW),
        ..row_at(NOW)
    };
    assert!(matches!(attempt(&setup, &closed, NOW).await, Err(SignError::Closed)));
    assert!(nothing_happened(&setup));
    setup
        .db
        .borrow_mut()
        .sessions
        .iter_mut()
        .for_each(|stored| stored.row.closed_at = Some(NOW));
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::Closed)));
    assert!(setup.db.borrow().signed.is_empty());
    assert!(lock_gate(&setup.gate).pending.is_empty());
    assert!(setup.allocations.borrow().is_empty());
    assert_eq!(setup.db.borrow().statements, vec![CLAIM_SQL, SIGN_STATE_SQL]);
    Ok(())
}


#[tokio::test]
async fn the_delay_bound_is_exact_and_a_future_row_is_stale() -> TestResult {
    let setup = setup()?;
    let delay = i64::try_from(MAX_SIGN_DELAY_SECONDS)?;
    let late = SessionRow {
        opened_at: NOW - delay - 1,
        ..row_at(NOW)
    };
    assert!(matches!(attempt(&setup, &late, NOW).await, Err(SignError::Stale)));
    let future = SessionRow {
        opened_at: NOW + delay,
        ..row_at(NOW)
    };
    assert!(matches!(attempt(&setup, &future, NOW).await, Err(SignError::Stale)));
    assert!(nothing_happened(&setup));
    let exact = SessionRow {
        opened_at: NOW - delay,
        ..row_at(NOW)
    };
    setup.db.borrow_mut().sessions.clear();
    seed(&setup, &exact);
    assert!(attempt(&setup, &exact, NOW).await.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_row_outside_its_grammar_is_refused_before_any_statement() -> TestResult {
    let setup = setup()?;
    let broken = [
        (
            "session_id",
            SessionRow {
                session_id: "-x".to_owned(),
                ..row_at(NOW)
            },
        ),
        (
            "asset",
            SessionRow {
                asset: String::new(),
                ..row_at(NOW)
            },
        ),
        (
            "ticket",
            SessionRow {
                ticket: "a b".to_owned(),
                ..row_at(NOW)
            },
        ),
        (
            "requester",
            SessionRow {
                requester: "a b".to_owned(),
                ..row_at(NOW)
            },
        ),
        (
            "requester",
            SessionRow {
                requester: "-alice".to_owned(),
                ..row_at(NOW)
            },
        ),
    ];
    for (field, row) in &broken {
        let refused = matches!(attempt(&setup, row, NOW).await, Err(SignError::Invalid { field: named }) if named == *field);
        assert!(refused, "{field} was not refused by name");
    }
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn a_session_id_the_agent_refuses_is_refused_before_the_record() -> TestResult {
    let mut setup = setup()?;
    let slashed = SessionRow {
        session_id: "sess/1".to_owned(),
        ..row_at(NOW)
    };
    setup.evidence.mfa = setup.evidence.mfa.map(|proof| MfaProof {
        request_id: "sess/1".to_owned(),
        ..proof
    });
    seed(&setup, &slashed);
    assert!(matches!(attempt(&setup, &slashed, NOW).await, Err(SignError::Action(_))));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn an_approver_with_a_leading_dash_touches_neither_record_nor_gate() -> TestResult {
    let mut setup = setup()?;
    setup.criticality = Some(Criticality::Critical);
    setup.evidence.approvals = vec![Approval {
        request_id: SESSION.to_owned(),
        tenant: ACME.to_owned(),
        approver: "-bob".to_owned(),
        approved_at: NOW - MFA_AGO,
    }];
    setup.evidence.approver_roles = BTreeMap::from([("-bob".to_owned(), roles(&["approver"]))]);
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::Action(_))));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn an_unknown_asset_and_another_tenants_map_are_refused() -> TestResult {
    let mut setup = setup()?;
    setup.agents.agents.clear();
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::UnknownAsset)));
    setup.agents = agent_map(GLOBEX, "agent-g");
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::UnknownAsset)));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn a_clock_before_the_epoch_or_at_the_end_of_time_is_refused() -> TestResult {
    let mut setup = setup()?;
    assert!(matches!(attempt(&setup, &row_at(NOW), -1).await, Err(SignError::Clock)));
    let late = i64::MAX - CLOCK_MARGIN;
    setup.evidence = evidence_at(late);
    assert!(matches!(attempt(&setup, &row_at(late), late).await, Err(SignError::Clock)));
    assert!(nothing_happened(&setup));
    Ok(())
}


#[tokio::test]
async fn two_calls_for_one_session_give_one_envelope_and_one_gate_entry() -> TestResult {
    let setup = setup()?;
    let first = attempt(&setup, &row_at(NOW), NOW).await;
    let second = attempt(&setup, &row_at(NOW), NOW).await;
    assert!(first.is_ok());
    assert!(matches!(second, Err(SignError::AlreadySigned)));
    assert_eq!(setup.db.borrow().signed.len(), 1);
    assert_eq!(lock_gate(&setup.gate).pending.len(), 1);
    assert_eq!(setup.allocations.borrow().len(), 1);
    Ok(())
}


#[tokio::test]
async fn the_same_session_for_another_agent_is_refused_at_the_record_and_never_reaches_the_gate() -> TestResult {
    let mut setup = setup()?;
    attempt(&setup, &row_at(NOW), NOW).await?;
    setup.agents = agent_map(ACME, "agent-b");
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::AlreadySigned)));
    assert_eq!(lock_gate(&setup.gate).pending.len(), 1);
    assert!(!gate_has_pending(&setup.gate, &identity("agent-b")));
    assert!(gate_has_pending(&setup.gate, &identity("agent-a")));
    assert_eq!(setup.allocations.borrow().len(), 1);
    Ok(())
}


#[tokio::test]
async fn an_unknown_session_or_another_open_time_is_a_row_mismatch() -> TestResult {
    let setup = setup()?;
    let unknown = row_at(NOW);
    setup.db.borrow_mut().sessions.clear();
    assert!(matches!(attempt(&setup, &unknown, NOW).await, Err(SignError::RowMismatch)));
    seed(&setup, &row_at(NOW));
    let other_time = SessionRow {
        opened_at: NOW - OPENED_AGO - 1,
        ..row_at(NOW)
    };
    assert!(matches!(attempt(&setup, &other_time, NOW).await, Err(SignError::RowMismatch)));
    assert!(setup.db.borrow().signed.is_empty());
    assert!(lock_gate(&setup.gate).pending.is_empty());
    Ok(())
}


fn unexpired_rows(setup: &Setup, count: usize, expires_at: Seconds) {
    (0..count).for_each(|index| {
        setup.db.borrow_mut().signed.push(Signed {
            tenant: ACME.to_owned(),
            session_id: format!("old-{index}"),
            agent_id: format!("agent-{index}"),
            approvers: String::new(),
            max_seconds: 1,
            idle_seconds: 1,
            issued_at: NOW,
            expires_at,
            key_id: "shell-key".to_owned(),
            sequence: Some(1),
        })
    });
}


#[tokio::test]
async fn the_per_tenant_cap_counts_only_unexpired_rows() -> TestResult {
    let setup = setup()?;
    assert_eq!(usize::try_from(MAX_PENDING_SHELLS_PER_TENANT)?, TENANT_CAP);
    unexpired_rows(&setup, TENANT_CAP, NOW + 1);
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::TenantFull)));
    assert!(lock_gate(&setup.gate).pending.is_empty());
    assert!(setup.allocations.borrow().is_empty());
    setup.db.borrow_mut().signed.clear();
    unexpired_rows(&setup, TENANT_CAP - 1, NOW + 1);
    unexpired_rows(&setup, 1, NOW - 1);
    assert!(attempt(&setup, &row_at(NOW), NOW).await.is_ok());
    Ok(())
}


#[tokio::test]
async fn a_claim_refused_for_no_visible_reason_is_unclaimed() -> TestResult {
    let setup = setup()?;
    setup.db.borrow_mut().refuse_claim = true;
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::Unclaimed)));
    assert!(lock_gate(&setup.gate).pending.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_full_gate_signs_nothing_and_the_session_stays_burnt() -> TestResult {
    let setup = setup()?;
    (0..TENANT_CAP).try_for_each(|index| gate_add(&setup.gate, ACME, &format!("filler-{index}"), "filler", NOW.unsigned_abs() + 1, 1))?;
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Gate(GateError::TenantFull))
    ));
    assert!(setup.allocations.borrow().is_empty());
    assert_eq!(setup.db.borrow().signed.len(), 1);
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::AlreadySigned)));
    Ok(())
}


#[tokio::test]
async fn a_duplicate_gate_key_is_refused_by_name() -> TestResult {
    let setup = setup()?;
    gate_add(&setup.gate, ACME, "agent-a", SESSION, NOW.unsigned_abs() + 1, 1)?;
    assert!(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Gate(GateError::Duplicate))
    ));
    assert!(setup.allocations.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn the_sequence_is_the_allocators_never_a_private_counter() -> TestResult {
    let mut setup = setup()?;
    setup.plan = SequencePlan::Fixed(FIXED_SEQUENCE);
    let signed = attempt(&setup, &row_at(NOW), NOW).await?;
    let (_, command) = decoded(&signed)?;
    assert_eq!(command.sequence, FIXED_SEQUENCE);
    assert!(setup.db.borrow().signed.iter().all(|entry| entry.sequence == Some(FIXED_SEQUENCE_STORED)));
    Ok(())
}


#[tokio::test]
async fn signing_failures_return_no_envelope_and_burn_the_session() -> TestResult {
    let mut setup = setup()?;
    setup.plan = SequencePlan::Fail;
    assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::Sequence(_))));
    let mut nonce = self::setup()?;
    nonce.fill = failing_fill;
    assert!(matches!(attempt(&nonce, &row_at(NOW), NOW).await, Err(SignError::Nonce(_))));
    let mut signer = self::setup()?;
    signer.signer = Box::new(|_message| -> Result<Vec<u8>, BoxError> { Err("signer down".into()) });
    assert!(matches!(attempt(&signer, &row_at(NOW), NOW).await, Err(SignError::Sign(_))));
    let mut huge = self::setup()?;
    huge.plan = SequencePlan::Fixed(u64::MAX);
    assert!(matches!(
        attempt(&huge, &row_at(NOW), NOW).await,
        Err(SignError::Store(StoreError::OutOfRange { .. }))
    ));
    [&setup, &nonce, &signer, &huge].iter().try_for_each(|burnt| {
        let recorded = burnt.db.borrow().signed.len() == 1;
        recorded.then_some(()).ok_or("the burnt session was not recorded")
    })?;
    Ok(())
}


#[tokio::test]
async fn a_store_failure_is_returned_at_each_statement() -> TestResult {
    let claim = setup()?;
    claim.db.borrow_mut().fail_on = Some(CLAIM_SQL);
    assert!(matches!(attempt(&claim, &row_at(NOW), NOW).await, Err(SignError::Store(_))));
    assert!(lock_gate(&claim.gate).pending.is_empty());
    let state = setup()?;
    state.db.borrow_mut().refuse_claim = true;
    state.db.borrow_mut().fail_on = Some(SIGN_STATE_SQL);
    assert!(matches!(attempt(&state, &row_at(NOW), NOW).await, Err(SignError::Store(_))));
    let sequence = setup()?;
    sequence.db.borrow_mut().fail_on = Some(SEQUENCE_SQL);
    assert!(matches!(attempt(&sequence, &row_at(NOW), NOW).await, Err(SignError::Store(_))));
    let empty = setup()?;
    empty.db.borrow_mut().empty_sequence = true;
    assert!(matches!(attempt(&empty, &row_at(NOW), NOW).await, Err(SignError::SequenceRecord)));
    Ok(())
}


async fn refused_read(edit: Edit) -> Result<bool, Box<dyn Error>> {
    let setup = setup()?;
    setup.db.borrow_mut().refuse_claim = true;
    setup.db.borrow_mut().edit_state = Some(edit);
    Ok(matches!(
        attempt(&setup, &row_at(NOW), NOW).await,
        Err(SignError::Store(StoreError::BadRow { .. }))
    ))
}


#[tokio::test]
async fn a_malformed_state_read_is_a_store_error_never_a_guess() -> TestResult {
    for column in UNREADABLE_COLUMNS {
        assert!(refused_read(Edit::Unreadable(column)).await?, "unreadable column {column} was accepted");
    }
    for column in REQUIRED_COLUMNS {
        assert!(refused_read(Edit::Null(column)).await?, "null column {column} was accepted");
    }
    for length in 0..STATE_COLUMNS {
        assert!(refused_read(Edit::Truncate(length)).await?, "a row cut to {length} columns was accepted");
    }
    Ok(())
}


#[tokio::test]
async fn no_refusal_carries_a_row_value() -> TestResult {
    let setup = setup()?;
    let marked = [
        SessionRow {
            session_id: format!("s-{MARKER}"),
            ..row_at(NOW)
        },
        SessionRow {
            asset: format!("a-{MARKER}"),
            ..row_at(NOW)
        },
        SessionRow {
            ticket: format!("t {MARKER}"),
            ..row_at(NOW)
        },
        SessionRow {
            requester: format!("-r-{MARKER}"),
            ..row_at(NOW)
        },
        SessionRow {
            requester: format!("r-{MARKER}"),
            asset: format!("a-{MARKER}"),
            ..row_at(NOW)
        },
        SessionRow {
            session_id: format!("{MARKER}/x"),
            ..row_at(NOW)
        },
    ];
    for row in &marked {
        let error = attempt(&setup, row, NOW).await.err().ok_or("the marked row was signed")?;
        let chain: Vec<&dyn Error> = std::iter::successors(Some(&error as &dyn Error), |inner| (*inner).source()).collect();
        let text: String = chain.iter().map(|inner| format!("{inner} {inner:?}")).collect();
        assert!(!text.contains(MARKER), "a value leaked: {text}");
    }
    Ok(())
}


#[tokio::test]
async fn the_statements_are_scoped_by_tenant_and_the_migration_is_registered() -> TestResult {
    assert!(SIGN_STATE_SQL.matches("tenant = $1").count() >= STATE_SCOPED_TWICE);
    assert!(SEQUENCE_SQL.contains("tenant = $1"));
    assert!(CLAIM_SQL.contains("$14") && CLAIM_SQL.contains("$1,"));
    assert_eq!(MIGRATION_NAMESPACE, "remote_shell");
    assert!(MIGRATIONS
        .iter()
        .any(|migration| migration.version == "rshell_0005" && migration.sql.contains("remote_shell_sign_claim")));
    Ok(())
}


#[tokio::test]
async fn a_register_row_that_differs_in_any_field_is_a_row_mismatch() -> TestResult {
    let differing = [
        SessionRow {
            requester: "carol".to_owned(),
            ..row_at(NOW)
        },
        SessionRow {
            asset: "host-8".to_owned(),
            ..row_at(NOW)
        },
        SessionRow {
            ticket: "INC-2".to_owned(),
            ..row_at(NOW)
        },
    ];
    for stored in &differing {
        let setup = setup()?;
        setup.db.borrow_mut().sessions.clear();
        seed(&setup, stored);
        assert!(matches!(attempt(&setup, &row_at(NOW), NOW).await, Err(SignError::RowMismatch)));
        assert!(setup.db.borrow().signed.is_empty());
        assert!(lock_gate(&setup.gate).pending.is_empty());
    }
    Ok(())
}
