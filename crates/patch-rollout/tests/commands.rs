#[path = "common/types.rs"]
mod types;


use agent_command::codec::{decode_exact, signing_message};
use agent_command::error::SignError;
use agent_command::model::{Action as AgentAction, Command, Envelope, KeyClass, PackageSelection, RebootPolicy, MAX_LIFETIME_SECONDS};
use agent_command::sign::{memory_signer, os_random};
use agent_command::types::{FillFn, SignerFn};
use ed25519_dalek::{Signature, SigningKey};
use patch_rollout::commands::{agent_action, deadline_in_bounds, signed_commands, SignedCommand, Signing};
use patch_rollout::error::{CommandError, RolloutError, StepError};
use patch_rollout::limits::RolloutLimits;
use patch_rollout::model::{DevicePhase, DeviceState, RingState, RingStatus, RolloutPolicy, StepKind};
use patch_rollout::policy::parse_policy;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;
use types::TestResult;


const NOW: u64 = 1_800_000_000;


const LIFETIME: u64 = 300;


const WINDOW: u64 = 3600;


const SEED: u8 = 7;


const SEED_LENGTH: usize = 32;


const KEY_ID: &str = "rollout-key";


const AGES_AGO: i64 = 1_000_000;


const SECOND_CALL: usize = 2;


const FIRST_SEQUENCE: u64 = 1;


const SECOND_SEQUENCE: u64 = 2;


const OVER_BY: u64 = 2;


fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[SEED; SEED_LENGTH])
}


fn policy_text(reboot_outside_window: bool) -> String {
    format!(
        "tenant: acme
reboot_outside_window: {reboot_outside_window}
groups:
  ws: {{window: weekend, devices: [w1], workstation: true}}
  srv: {{window: night, devices: [s1, s2]}}
rings:
  - {{name: all, groups: [ws, srv], soak_seconds: 0, max_failures: 5, max_failure_percent: 100}}
"
    )
}


fn policy(reboot_outside_window: bool) -> Result<RolloutPolicy, Box<dyn std::error::Error>> {
    Ok(parse_policy(&policy_text(reboot_outside_window), "p.yaml", &RolloutLimits::default())?)
}


fn now() -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    Ok(OffsetDateTime::from_unix_timestamp(i64::try_from(NOW)?)?)
}


fn device(tenant: &str, id: &str, phase: DevicePhase, in_window: bool) -> DeviceState {
    DeviceState {
        tenant: tenant.to_owned(),
        device: id.to_owned(),
        phase,
        in_window,
    }
}


fn fail_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


struct Setup {
    deadline: u64,
    lifetime: u64,
    fill: FillFn,
    signer: Box<SignerFn>,
}


fn setup() -> Setup {
    Setup {
        deadline: NOW + LIFETIME,
        lifetime: LIFETIME,
        fill: os_random,
        signer: memory_signer(signing_key()),
    }
}


fn run(
    reboot_outside_window: bool,
    devices: &[DeviceState],
    rings: &[RingState],
    setup: &Setup,
) -> Result<Vec<SignedCommand>, Box<dyn std::error::Error>> {
    let mut counter: u64 = 0;
    let mut next = |_class: KeyClass| {
        counter += 1;
        counter
    };
    let mut signing = Signing {
        key_id: KEY_ID,
        lifetime_seconds: setup.lifetime,
        window_seconds: WINDOW,
        reboot_deadline: setup.deadline,
        next_sequence: &mut next,
        fill: setup.fill,
        signer: setup.signer.as_ref(),
    };
    Ok(signed_commands(
        &policy(reboot_outside_window)?,
        rings,
        devices,
        now()?,
        &RolloutLimits::default(),
        &mut signing,
    )?)
}


fn decode(signed: &SignedCommand) -> Result<Command, Box<dyn std::error::Error>> {
    let envelope: Envelope = decode_exact(&signed.envelope)?;
    let signature = Signature::from_slice(&envelope.signature)?;
    signing_key()
        .verifying_key()
        .verify_strict(&signing_message(&envelope.command), &signature)?;
    assert_eq!(envelope.key_id, KEY_ID);
    Ok(decode_exact(&envelope.command)?)
}


fn only(signed: &[SignedCommand]) -> Result<Command, Box<dyn std::error::Error>> {
    decode(signed.first().ok_or("no command")?)
}


#[test]
fn installs_are_signed_one_per_device_with_increasing_sequences() -> TestResult {
    let devices = [
        device("acme", "s1", DevicePhase::Pending, true),
        device("acme", "s2", DevicePhase::Pending, true),
        device("acme", "w1", DevicePhase::Pending, false),
    ];
    let signed = run(false, &devices, &[], &setup())?;
    assert_eq!(signed.len(), SECOND_CALL);
    let first = decode(signed.first().ok_or("none")?)?;
    let second = decode(signed.get(1).ok_or("none")?)?;
    assert_eq!((first.sequence, second.sequence), (FIRST_SEQUENCE, SECOND_SEQUENCE));
    assert_eq!((first.agent_id.as_str(), second.agent_id.as_str()), ("s1", "s2"));
    assert_eq!(first.tenant, "acme");
    assert_eq!(first.key_class, KeyClass::Sensitive);
    assert_eq!(first.expires_at - first.issued_at, LIFETIME);
    assert!(first.expires_at - first.issued_at <= MAX_LIFETIME_SECONDS);
    assert_eq!(
        first.action,
        AgentAction::InstallUpdates {
            packages: PackageSelection::AllAllowed,
            reboot: RebootPolicy::Never
        }
    );
    Ok(())
}


#[test]
fn a_reboot_outside_the_window_needs_the_policy_flag() -> TestResult {
    let devices = [device("acme", "s1", DevicePhase::NeedsReboot, false)];
    assert!(run(false, &devices, &[], &setup())?.is_empty());
    let command = only(&run(true, &devices, &[], &setup())?)?;
    assert_eq!(
        command.action,
        AgentAction::Reboot {
            prompt_user: false,
            deadline: NOW + LIFETIME
        }
    );
    Ok(())
}


#[test]
fn a_workstation_reboot_prompts_the_user_first() -> TestResult {
    let prompt = only(&run(false, &[device("acme", "w1", DevicePhase::NeedsReboot, true)], &[], &setup())?)?;
    assert!(matches!(prompt.action, AgentAction::Reboot { prompt_user: true, .. }));
    let after = only(&run(false, &[device("acme", "w1", DevicePhase::RebootPrompted, true)], &[], &setup())?)?;
    assert!(matches!(after.action, AgentAction::Reboot { prompt_user: false, .. }));
    Ok(())
}


#[test]
fn outcomes_without_actions_sign_nothing() -> TestResult {
    let finished = RingState {
        tenant: "acme".to_owned(),
        ring: "all".to_owned(),
        status: RingStatus::Finished {
            at: OffsetDateTime::from_unix_timestamp(i64::try_from(NOW)? - AGES_AGO)?,
        },
    };
    let devices = [device("acme", "s1", DevicePhase::Pending, true)];
    assert!(run(false, &devices, &[finished], &setup())?.is_empty());
    Ok(())
}


#[test]
fn a_device_of_another_tenant_never_yields_a_command() -> TestResult {
    let devices = [
        device("acme", "s1", DevicePhase::Pending, true),
        device("other", "s2", DevicePhase::Pending, true),
    ];
    let refused = run(false, &devices, &[], &setup()).err().ok_or("signed")?;
    assert!(matches!(
        refused.downcast_ref::<CommandError>(),
        Some(CommandError::Rollout(RolloutError::TenantMismatch { .. }))
    ));
    Ok(())
}


#[test]
fn a_signer_failure_stops_the_batch_and_counts_the_signed() -> TestResult {
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let inner = memory_signer(signing_key());
    let failing: Box<SignerFn> = Box::new(move |message| {
        if seen.fetch_add(1, Ordering::SeqCst) + 1 >= SECOND_CALL {
            Err("vault unreachable".into())
        } else {
            inner(message)
        }
    });
    let mut chosen = setup();
    chosen.signer = failing;
    let devices = [
        device("acme", "s1", DevicePhase::Pending, true),
        device("acme", "s2", DevicePhase::Pending, true),
    ];
    let refused = run(false, &devices, &[], &chosen).err().ok_or("signed")?;
    assert!(matches!(
        refused.downcast_ref::<CommandError>(),
        Some(CommandError::Batch {
            signed: 1,
            source: StepError::Sign(SignError::Signer(_))
        })
    ));
    assert!(refused.to_string().contains("signing 1 commands"));
    assert_eq!(calls.load(Ordering::SeqCst), SECOND_CALL);
    Ok(())
}


#[test]
fn a_nonce_failure_stops_the_batch() -> TestResult {
    let mut chosen = setup();
    chosen.fill = fail_fill;
    let refused = run(false, &[device("acme", "s1", DevicePhase::Pending, true)], &[], &chosen)
        .err()
        .ok_or("signed")?;
    assert!(matches!(
        refused.downcast_ref::<CommandError>(),
        Some(CommandError::Batch {
            signed: 0,
            source: StepError::Nonce(_)
        })
    ));
    Ok(())
}


#[test]
fn a_reboot_deadline_outside_its_bounds_is_refused_at_signing() -> TestResult {
    let devices = [device("acme", "s1", DevicePhase::NeedsReboot, true)];
    let mut chosen = setup();
    chosen.deadline = NOW + LIFETIME + WINDOW + 1;
    let late = run(false, &devices, &[], &chosen).err().ok_or("signed")?;
    assert!(matches!(
        late.downcast_ref::<CommandError>(),
        Some(CommandError::Batch {
            signed: 0,
            source: StepError::DeadlineOutOfBounds
        })
    ));
    chosen.deadline = NOW - 1;
    assert!(run(false, &devices, &[], &chosen).is_err());
    chosen.deadline = NOW + LIFETIME + WINDOW;
    assert!(run(false, &devices, &[], &chosen).is_ok());
    let installs = [device("acme", "s1", DevicePhase::Pending, true)];
    chosen.deadline = 0;
    assert!(run(false, &installs, &[], &chosen).is_ok());
    Ok(())
}


#[test]
fn the_lifetime_and_the_clock_are_bounded() -> TestResult {
    let devices = [device("acme", "s1", DevicePhase::Pending, true)];
    let mut chosen = setup();
    chosen.lifetime = 0;
    assert!(run(false, &devices, &[], &chosen).is_err());
    chosen.lifetime = MAX_LIFETIME_SECONDS + OVER_BY;
    let refused = run(false, &devices, &[], &chosen).err().ok_or("signed")?;
    assert!(matches!(
        refused.downcast_ref::<CommandError>(),
        Some(CommandError::LifetimeOutOfBounds { .. })
    ));
    chosen.lifetime = MAX_LIFETIME_SECONDS;
    assert!(run(false, &devices, &[], &chosen).is_ok());
    let mut counter: u64 = 0;
    let mut next = |_class: KeyClass| {
        counter += 1;
        counter
    };
    let mut signing = Signing {
        key_id: KEY_ID,
        lifetime_seconds: LIFETIME,
        window_seconds: WINDOW,
        reboot_deadline: 0,
        next_sequence: &mut next,
        fill: os_random,
        signer: chosen.signer.as_ref(),
    };
    let before_epoch = signed_commands(
        &policy(false)?,
        &[],
        &devices,
        OffsetDateTime::from_unix_timestamp(-1)?,
        &RolloutLimits::default(),
        &mut signing,
    );
    assert!(matches!(before_epoch, Err(CommandError::ClockBeforeEpoch)));
    Ok(())
}


#[test]
fn the_mapping_and_the_bounds_are_exact() -> TestResult {
    assert!(matches!(agent_action(StepKind::Install, 0), AgentAction::InstallUpdates { .. }));
    assert!(deadline_in_bounds(StepKind::Reboot, NOW, NOW, NOW, 0));
    assert!(!deadline_in_bounds(StepKind::Reboot, NOW + 1, NOW, NOW, 0));
    assert!(!deadline_in_bounds(StepKind::PromptReboot, NOW - 1, NOW, NOW, WINDOW));
    assert!(deadline_in_bounds(StepKind::Install, 0, NOW, NOW, 0));
    Ok(())
}
