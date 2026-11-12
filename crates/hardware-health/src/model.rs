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
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    BlindSpot(BlindReason),
    Failing,
    PredictiveFailure(Vec<String>),
    Healthy,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Measure {
    pub name: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<(String, String)>,
}
