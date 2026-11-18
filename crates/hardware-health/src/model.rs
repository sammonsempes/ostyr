//! Data types, no logic.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_attributes: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Ata,
    Nvme,
    Scsi,
    Other(String),
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFailed {
    Now,
    Past,
    Never,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub id: u64,
    pub name: Option<String>,
    pub value: Option<u64>,
    pub worst: Option<u64>,
    pub threshold: Option<u64>,
    pub when_failed: Option<WhenFailed>,
    pub prefailure: Option<bool>,
    pub raw_value: Option<u64>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NvmeHealth {
    pub critical_warning: Option<u64>,
    pub available_spare: Option<u64>,
    pub available_spare_threshold: Option<u64>,
    pub percentage_used: Option<u64>,
    pub media_errors: Option<u64>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartReport {
    pub device_name: Option<String>,
    pub protocol: Option<Protocol>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub exit_status: Option<u8>,
    pub smart_passed: Option<bool>,
    pub temperature_celsius: Option<i64>,
    pub power_on_hours: Option<u64>,
    pub attributes: Vec<Attribute>,
    pub omitted_attributes: usize,
    pub nvme: Option<NvmeHealth>,
    pub rejected_fields: usize,
    pub format_major: Option<u64>,
    pub unreadable_health: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindReason {
    ExitStatusMissing,
    CommandFailed(u8),
    NoVerdict,
    UnknownFormat,
    UnreadableHealthField(String),
    TooManyAttributes,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    BlindSpot(BlindReason),
    Failing,
    PredictiveFailure(Vec<String>),
    Degraded(Vec<String>),
    Healthy,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Measure {
    pub name: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<(String, String)>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpsFlag {
    Online,
    OnBattery,
    LowBattery,
    ReplaceBattery,
    Charging,
    Discharging,
    Bypass,
    Overload,
    Trim,
    Boost,
    ForcedShutdown,
    Alarm,
    Off,
    HighBattery,
    Calibrating,
    Test,
    NoComm,
}


#[derive(Debug, Clone, PartialEq)]
pub struct UpsReport {
    pub status: Option<std::collections::BTreeSet<UpsFlag>>,
    pub battery_charge: Option<f64>,
    pub battery_runtime: Option<f64>,
    pub input_voltage: Option<f64>,
    pub output_voltage: Option<f64>,
    pub load: Option<f64>,
    pub temperature: Option<f64>,
    pub rejected_fields: usize,
    pub unreadable: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsThresholds {
    #[serde(default = "crate::limits::default_min_battery_charge")]
    pub min_battery_charge: u8,
    #[serde(default = "crate::limits::default_min_runtime_seconds")]
    pub min_runtime_seconds: u32,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedfishLimits {
    pub max_bytes: u64,
    pub max_sensors: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedfishHealth {
    Ok,
    Warning,
    Critical,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedfishState {
    Enabled,
    Disabled,
    StandbyOffline,
    StandbySpare,
    InTest,
    Starting,
    Absent,
    UnavailableOffline,
    Deferring,
    Quiesced,
    Updating,
    Qualified,
    Degraded,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading<Value> {
    Found(Value),
    Unreadable,
    Missing,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    Chassis,
    System,
    Temperature,
    Fan,
    PowerSupply,
    Voltage,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub kind: ComponentKind,
    pub index: usize,
    pub name: Option<String>,
    pub health: Reading<RedfishHealth>,
    pub state: Reading<RedfishState>,
    pub reading: Reading<f64>,
    pub upper_critical: Reading<f64>,
    pub unit: &'static str,
}


#[derive(Debug, Clone, PartialEq)]
pub struct RedfishReport {
    pub components: Vec<Component>,
    pub chassis_rollup: Reading<RedfishHealth>,
    pub system_rollup: Reading<RedfishHealth>,
    pub missing_documents: Vec<&'static str>,
    pub refused_collections: Vec<&'static str>,
    pub unreadable: Vec<&'static str>,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedfishDevice {
    pub name: String,
    pub base_url: String,
    pub ca_file: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    pub username: String,
    pub password_file: String,
    pub timeout_ms: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedfishDeviceFile {
    pub devices: Vec<RedfishDevice>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleCheck {
    NotAdministrator,
    Administrator,
    Unknown,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReport {
    pub device: String,
    pub tenant: String,
    pub health: Health,
    pub unverified_tls: bool,
    pub role: RoleCheck,
}


pub struct FetchSession {
    pub agent: ureq::Agent,
    pub auth: zeroize::Zeroizing<String>,
    pub base: String,
    pub deadline: std::time::Instant,
    pub max_bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartSettings {
    #[serde(default = "crate::limits::default_smartctl")]
    pub program: std::path::PathBuf,
    #[serde(default = "crate::limits::default_deadline_seconds")]
    pub deadline_seconds: u64,
    #[serde(default = "crate::limits::default_round_deadline_seconds")]
    pub round_deadline_seconds: u64,
}


/// Why one smartctl run produced no report; a category only, never output or stderr text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FailureClass {
    #[error("smartctl passed its deadline")]
    TimedOut,
    #[error("smartctl output is over the cap")]
    TooLarge,
    #[error("smartctl could not be started")]
    Spawn,
    #[error("smartctl run failed on an I/O error")]
    Io,
    #[error("the smartctl child cannot be waited on")]
    Unwaitable,
    #[error("smartctl was ended by a signal")]
    Signalled,
    #[error("smartctl refused its command line")]
    CommandLine,
    #[error("smartctl could not open the device")]
    OpenFailed,
    #[error("smartctl output is not readable")]
    Unparsable,
    #[error("the scan lists too many devices")]
    TooManyDevices,
    #[error("the smartctl program is not trusted")]
    ProgramRefused,
    #[error("the round deadline passed before this device was read")]
    Deferred,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub bytes: Vec<u8>,
    pub exit_code: Option<i32>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunReport {
    pub scan_failed: Option<FailureClass>,
    pub reports: Vec<(String, SmartReport)>,
    pub refused_devices: usize,
    pub failed: Vec<(String, FailureClass)>,
}
