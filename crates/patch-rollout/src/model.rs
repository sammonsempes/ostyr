use response_breakers::model::ProposedAction;
use serde::Deserialize;
use std::collections::BTreeMap;
use time::OffsetDateTime;


/// `window` names the maintenance window the caller resolves into `DeviceState::in_window`; a workstation always gets a reboot prompt.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPolicy {
    pub window: String,
    pub devices: Vec<String>,
    #[serde(default)]
    pub workstation: bool,
    #[serde(default)]
    pub prompt_before_reboot: bool,
}


/// A ring is over its threshold when failures exceed `max_failures`, or exceed `max_failure_percent` of its devices.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingPolicy {
    pub name: String,
    pub groups: Vec<String>,
    pub soak_seconds: u32,
    pub max_failures: usize,
    pub max_failure_percent: usize,
}


/// `rings` run in order, the pilot first.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutPolicy {
    pub tenant: String,
    #[serde(default)]
    pub reboot_outside_window: bool,
    pub groups: BTreeMap<String, GroupPolicy>,
    pub rings: Vec<RingPolicy>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingStatus {
    NotStarted,
    Running,
    Finished { at: OffsetDateTime },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingState {
    pub tenant: String,
    pub ring: String,
    pub status: RingStatus,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePhase {
    Pending,
    NeedsReboot,
    RebootPrompted,
    Failed,
    Done,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    pub tenant: String,
    pub device: String,
    pub phase: DevicePhase,
    pub in_window: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    Install,
    PromptReboot,
    Reboot,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub device: String,
    pub kind: StepKind,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferReason {
    OutsideWindow,
    DeviceCap,
    RingCap,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    pub subject: String,
    pub reason: DeferReason,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Act(Action),
    Defer(Deferred),
    Nothing,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    UnknownDevice(String),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    FailureCount { failed: usize, max: usize },
    FailurePercent { failed: usize, total: usize, max_percent: usize },
}


/// `breaker_input` is the action to pass through `response_breakers::check`: an RMM execution over every device of the ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    pub ring: String,
    pub reason: StopReason,
    pub breaker_input: ProposedAction,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Capped,
    Stop(Stop),
    Waiting { ring: String, until: OffsetDateTime },
    Proceed { ring: String, actions: Vec<Action> },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub deferred: Vec<Deferred>,
    pub issues: Vec<Issue>,
}
