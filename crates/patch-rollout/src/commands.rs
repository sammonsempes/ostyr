use crate::decide::next_actions;
use crate::error::{CommandError, StepError};
use crate::limits::RolloutLimits;
use crate::model::{Action, DeviceState, Outcome, RingState, RolloutPolicy, StepKind};
use crate::types::SequenceFn;
use agent_command::model::{Action as AgentAction, Command, KeyClass, PackageSelection, RebootPolicy, MAX_LIFETIME_SECONDS};
use agent_command::sign::{new_nonce, sign_command};
use agent_command::types::{FillFn, SignerFn};
use time::OffsetDateTime;


/// `reboot_deadline` is an absolute Unix time in seconds within `[issued_at, expires_at + window_seconds]`; the agent id is the device id.
pub struct Signing<'injected> {
    pub key_id: &'injected str,
    pub lifetime_seconds: u64,
    pub window_seconds: u64,
    pub reboot_deadline: u64,
    pub next_sequence: &'injected mut SequenceFn<'injected>,
    pub fill: FillFn,
    pub signer: &'injected SignerFn,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommand {
    pub device: String,
    pub envelope: Vec<u8>,
}


/// An install never reboots by itself: the reboot is its own step. A prompted reboot asks the user first, the one after the prompt does not.
pub fn agent_action(kind: StepKind, deadline: u64) -> AgentAction {
    match kind {
        StepKind::Install => AgentAction::InstallUpdates {
            packages: PackageSelection::AllAllowed,
            reboot: RebootPolicy::Never,
        },
        StepKind::PromptReboot => AgentAction::Reboot { prompt_user: true, deadline },
        StepKind::Reboot => AgentAction::Reboot {
            prompt_user: false,
            deadline,
        },
    }
}


pub fn deadline_in_bounds(kind: StepKind, deadline: u64, issued_at: u64, expires_at: u64, window_seconds: u64) -> bool {
    kind == StepKind::Install || (deadline >= issued_at && deadline <= expires_at.saturating_add(window_seconds))
}


pub fn sign_action(policy: &RolloutPolicy, action: &Action, issued_at: u64, signing: &mut Signing) -> Result<SignedCommand, StepError> {
    let expires_at = issued_at.saturating_add(signing.lifetime_seconds);
    if deadline_in_bounds(action.kind, signing.reboot_deadline, issued_at, expires_at, signing.window_seconds) {
        let nonce = new_nonce(signing.fill).map_err(StepError::Nonce)?;
        let command = Command {
            key_id: signing.key_id.to_owned(),
            key_class: KeyClass::Sensitive,
            agent_id: action.device.clone(),
            tenant: policy.tenant.clone(),
            issued_at,
            expires_at,
            sequence: (signing.next_sequence)(KeyClass::Sensitive),
            nonce,
            action: agent_action(action.kind, signing.reboot_deadline),
        };
        let envelope = sign_command(&command, signing.key_id, signing.signer).map_err(StepError::Sign)?;
        Ok(SignedCommand {
            device: action.device.clone(),
            envelope,
        })
    } else {
        Err(StepError::DeadlineOutOfBounds)
    }
}


/// Signs one command per `Proceed` action (tenant checked by `next_actions`); any other outcome signs nothing. A failure stops the batch and counts what was signed.
pub fn signed_commands(
    policy: &RolloutPolicy,
    ring_states: &[RingState],
    device_states: &[DeviceState],
    now: OffsetDateTime,
    limits: &RolloutLimits,
    signing: &mut Signing,
) -> Result<Vec<SignedCommand>, CommandError> {
    let decision = next_actions(policy, ring_states, device_states, now, limits)?;
    let issued_at = u64::try_from(now.unix_timestamp()).map_err(|_| CommandError::ClockBeforeEpoch)?;
    if signing.lifetime_seconds == 0 || signing.lifetime_seconds > MAX_LIFETIME_SECONDS {
        Err(CommandError::LifetimeOutOfBounds { max: MAX_LIFETIME_SECONDS })
    } else {
        let actions = match decision.outcome {
            Outcome::Proceed { actions, .. } => actions,
            _ => Vec::new(),
        };
        actions
            .iter()
            .try_fold(Vec::new(), |mut signed, action| match sign_action(policy, action, issued_at, signing) {
                Ok(command) => {
                    signed.push(command);
                    Ok(signed)
                }
                Err(source) => Err(CommandError::Batch {
                    signed: signed.len(),
                    source,
                }),
            })
    }
}
