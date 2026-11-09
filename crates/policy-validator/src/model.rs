use crate::types::DetectionCounts;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Sigma,
    Sysmon,
    Defender,
    Tetragon,
    YaraX,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Global,
    EndpointGroup,
    SingleEndpoint,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorKind {
    Hash,
    Path,
    ProcessName,
    CommandLine,
    Signer,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub kind: SelectorKind,
    pub value: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}


/// Assembled by the platform from telemetry, never taken from the proposer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub benign_verdicts: u32,
    pub distinct_days: u32,
    pub distinct_endpoints: u32,
    pub role_match: bool,
    pub original_severity: Severity,
    pub honeytoken_linked: bool,
    pub signed_by_trusted: bool,
    pub known_hash: Option<String>,
    pub observed_images: Vec<ObservedImage>,
}


/// An image seen running the excluded activity, filled by the platform from agent telemetry; a missing field refuses the proposal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedImage {
    pub path: String,
    pub sha256: String,
    pub name: String,
    pub original_file_name: Option<String>,
    pub os_component: bool,
    pub security_sensor: bool,
    pub writable_by_non_admin: bool,
}


/// `detections` is the current coverage map: detections per ATT&CK technique.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Impact {
    pub techniques: Vec<String>,
    pub detections: DetectionCounts,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub engine: Engine,
    pub scope: Scope,
    pub selector: Selector,
    pub lifetime_days: u32,
    pub evidence: Evidence,
    pub impact: Impact,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrState {
    Block,
    Warn,
    Audit,
    Disabled,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AsrChange {
    pub rule_id: String,
    pub new_state: AsrState,
    pub impact: Impact,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Proposal {
    Exclusion(Exclusion),
    AsrChange(AsrChange),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Error)]
#[serde(rename_all = "snake_case")]
pub enum PathForm {
    #[error("not absolute")]
    NotAbsolute,
    #[error("empty selector")]
    Empty,
    #[error("`.` or `..` segment")]
    DotSegment,
    #[error("environment variable")]
    EnvironmentVariable,
    #[error("wildcard")]
    Wildcard,
    #[error("tilde form")]
    Tilde,
    #[error("8.3 short name")]
    ShortName,
    #[error("UNC path")]
    Unc,
    #[error("NT device path")]
    NtDevice,
    #[error("drive-relative path")]
    DriveRelative,
    #[error("alternate stream or stray colon")]
    AlternateStream,
    #[error("trailing dot or space")]
    TrailingDotOrSpace,
    #[error("doubled separator")]
    DoubledSeparator,
    #[error("trailing separator")]
    TrailingSeparator,
    #[error("mixed separators")]
    MixedSeparators,
    #[error("control character")]
    ControlCharacter,
    #[error("reserved character")]
    ReservedCharacter,
    #[error("quoting or escape character")]
    Quoting,
    #[error("non-ASCII character")]
    NonAscii,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    #[error("path_at_wide_scope: only a hash is allowed at global or group scope")]
    PathAtWideScope,
    #[error("process_name_at_wide_scope: only a hash is allowed at global or group scope")]
    ProcessNameAtWideScope,
    #[error("command_line_at_wide_scope: only a hash is allowed at global or group scope")]
    CommandLineAtWideScope,
    #[error("signer_selector: a signer is wider than a hash or a path and is refused at every scope")]
    SignerSelector,
    #[error("non_canonical: {form}")]
    NonCanonical { form: PathForm },
    #[error("input_too_large: a field exceeds its size bound")]
    InputTooLarge,
    #[error("selector_not_in_evidence: the selector matches no observed image")]
    SelectorNotInEvidence,
    #[error("directory_selector: a path selector must equal an observed image path, not a directory")]
    DirectorySelector,
    #[error("os_directory: {directory}")]
    OsDirectory { directory: String },
    #[error("invalid_hash: expected 64 hexadecimal characters")]
    InvalidHash,
    #[error("system_binary: {name} is a configured interpreter or system binary")]
    SystemBinary { name: String },
    #[error("no_observed_image: an exclusion needs the observed images")]
    NoObservedImage,
    #[error("security_sensor: {name} is the agent or one of its sensors")]
    SecuritySensor { name: String },
    #[error("writable_by_non_admin: {name} or a parent directory is writable by a non-administrator")]
    WritableByNonAdmin { name: String },
    #[error("interpreter_in_command_line: {name}")]
    InterpreterInCommandLine { name: String },
    #[error("service_control_in_command_line: {name}")]
    ServiceControlInCommandLine { name: String },
    #[error("user_writable_directory: {directory}")]
    UserWritableDirectory { directory: String },
    #[error("protected_path: {directory}")]
    ProtectedPath { directory: String },
    #[error("unsigned_path: a path or process exclusion needs a signed binary")]
    UnsignedPath,
    #[error("unsigned_without_hash: an unsigned binary needs a known stable hash")]
    UnsignedWithoutHash,
    #[error("too_few_verdicts: {have} of {need}")]
    TooFewVerdicts { have: u32, need: u32 },
    #[error("too_few_days: {have} of {need}")]
    TooFewDays { have: u32, need: u32 },
    #[error("no_role_match: a single endpoint needs a role match")]
    NoRoleMatch,
    #[error("critical_alert: the original alert is critical")]
    CriticalAlert,
    #[error("honeytoken_linked: the original alert is linked to a honeytoken")]
    HoneytokenLinked,
    #[error("lifetime_too_long: {days} days, at most {max}")]
    LifetimeTooLong { days: u32, max: u32 },
    #[error("narrower_selector: use the known hash {hash}")]
    NarrowerSelector { hash: String },
    #[error("narrower_scope: only one endpoint was seen, use the single endpoint scope")]
    NarrowerScope,
    #[error("critical_asr_rule: {rule_id} must stay in block mode")]
    CriticalAsrRule { rule_id: Uuid },
    #[error("invalid_asr_rule_id: not a GUID")]
    InvalidAsrRuleId,
    #[error("coverage_loss: {technique} would be left without a detection")]
    CoverageLoss { technique: String },
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Accepted,
    Refused,
}


/// Every violated rule is listed; `version` is the crate version plus the configuration hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub version: String,
    pub decision: Decision,
    pub reasons: Vec<Reason>,
}
