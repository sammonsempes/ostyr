use crate::model::PathForm;
use crate::path::{canonical_path, CanonicalPath};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;


pub const MIN_BENIGN_VERDICTS: u32 = 5;


pub const MIN_DISTINCT_DAYS: u32 = 3;


pub const MAX_LIFETIME_DAYS: u32 = 90;


pub const DEFAULT_INTERPRETERS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "bash",
    "sh",
    "python",
    "python3",
    "perl",
    "node",
    "nodejs",
    "powershell_ise.exe",
    "pythonw.exe",
    "py.exe",
    "dash",
    "ksh",
    "zsh",
    "fish",
    "ruby",
    "php",
    "lua",
    "wsl.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "java",
    "javaw.exe",
    "jshell",
    "busybox",
    "certutil.exe",
    "wmic.exe",
    "bitsadmin.exe",
];


pub const DEFAULT_USER_WRITABLE_PREFIXES: &[&str] = &[
    r"C:\Users",
    r"C:\ProgramData",
    r"C:\Windows\Temp",
    r"C:\Windows\Tasks",
    r"C:\Documents and Settings",
    r"C:\Windows\System32\spool\drivers\color",
    r"C:\Windows\System32\Tasks",
    r"C:\Windows\Tracing",
    r"C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    r"C:\Windows\SysWOW64\Tasks",
    r"C:\Windows\System32\spool\PRINTERS",
    r"C:\Windows\System32\spool\SERVERS",
    r"C:\Windows\System32\com\dmp",
    r"C:\Windows\SysWOW64\com\dmp",
    r"C:\Windows\Registration\CRMLog",
    r"C:\Windows\debug\WIA",
    r"C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System",
    "/var/lib/php/sessions",
    "/var/lib/php5",
    "/var/cache",
    "/var/mail",
    "/proc",
    "/dev/mqueue",
    "/var/spool",
    "/tmp",
    "/var/tmp",
    "/usr/tmp",
    "/dev/shm",
    "/home",
    "/root",
    "/Users",
    "/run/user",
    "/var/run/user",
    "/run/lock",
    "/var/lock",
    "/var/crash",
    "/var/run/lock",
    r"C:\Windows\System32\FxsTmp",
    r"C:\Windows\SysWOW64\FxsTmp",
    r"C:\Windows\System32\Tasks_Migrated",
];


pub const DEFAULT_OS_DIRECTORIES: &[&str] = &[r"C:\Windows", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc"];


pub const DEFAULT_USER_WRITABLE_SEGMENTS: &[&str] = &["appdata", "downloads", "temp", "tmp"];


pub const DEFAULT_AGENT_PATHS: &[&str] = &[
    r"C:\Program Files\Ostyr",
    r"C:\ProgramData\Ostyr",
    "/opt/ostyr",
    "/var/lib/ostyr",
    "/etc/ostyr",
    r"C:\Windows\Sysmon.exe",
    r"C:\Windows\Sysmon64.exe",
    r"C:\Windows\SysmonDrv.sys",
    r"C:\Program Files\Windows Defender",
    r"C:\Program Files\Windows Defender Advanced Threat Protection",
    r"C:\ProgramData\Microsoft\Windows Defender",
    "/usr/bin/tetragon",
    "/usr/local/bin/tetragon",
    "/etc/tetragon",
    "/usr/bin/osqueryd",
    "/usr/local/bin/osqueryd",
    "/etc/osquery",
    "/opt/osquery",
    "/sys/fs/bpf",
];


pub const DEFAULT_SECURITY_SENSORS: &[&str] = &[
    "sysmon",
    "sysmondrv",
    "msmpeng",
    "mssense",
    "nissrv",
    "mpcmdrun",
    "osqueryd",
    "osqueryi",
    "tetragon",
    "tetragon-operator",
    "yara-x",
    "ostyr",
    "ostyr-agent",
];


pub const DEFAULT_SERVICE_TOOLS: &[&str] = &[
    "systemctl",
    "service",
    "sc",
    "net",
    "net1",
    "taskkill",
    "kill",
    "pkill",
    "killall",
    "launchctl",
    "fltmc",
    "wevtutil",
    "auditpol",
    "auditctl",
    "setenforce",
    "tamper",
    "bpftool",
];


pub const DEFAULT_OS_VENDOR_SIGNERS: &[&str] = &["microsoft windows", "microsoft corporation", "apple inc", "canonical", "red hat"];


pub const LSASS_CREDENTIAL_THEFT_RULE: Uuid = Uuid::from_u128(0x9e6c4e1f_7d60_472f_ba1a_a39ef669e4b2);


pub const EXECUTABLE_CONTENT_FROM_EMAIL_RULE: Uuid = Uuid::from_u128(0xbe9ba2d9_53ea_4cdc_84e5_9b1eeee46550);


pub const OFFICE_CHILD_PROCESS_RULE: Uuid = Uuid::from_u128(0xd4f940ab_401b_4efc_aadc_ad5f3c50688a);


/// The policy file: every field is optional and falls back to the defaults above; a list replaces the default list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub min_benign_verdicts: u32,
    pub min_distinct_days: u32,
    pub max_lifetime_days: u32,
    pub interpreters: Vec<String>,
    pub user_writable_prefixes: Vec<String>,
    pub user_writable_segments: Vec<String>,
    pub os_directories: Vec<String>,
    pub honeytoken_paths: Vec<String>,
    pub agent_paths: Vec<String>,
    pub security_sensors: Vec<String>,
    pub service_tools: Vec<String>,
    pub os_vendor_signers: Vec<String>,
    pub critical_asr_rules: Vec<Uuid>,
}


impl Default for Policy {
    fn default() -> Self {
        Self {
            min_benign_verdicts: MIN_BENIGN_VERDICTS,
            min_distinct_days: MIN_DISTINCT_DAYS,
            max_lifetime_days: MAX_LIFETIME_DAYS,
            interpreters: DEFAULT_INTERPRETERS.iter().map(|name| (*name).to_owned()).collect(),
            user_writable_prefixes: DEFAULT_USER_WRITABLE_PREFIXES.iter().map(|name| (*name).to_owned()).collect(),
            user_writable_segments: DEFAULT_USER_WRITABLE_SEGMENTS.iter().map(|name| (*name).to_owned()).collect(),
            os_directories: DEFAULT_OS_DIRECTORIES.iter().map(|name| (*name).to_owned()).collect(),
            honeytoken_paths: Vec::new(),
            agent_paths: DEFAULT_AGENT_PATHS.iter().map(|name| (*name).to_owned()).collect(),
            security_sensors: DEFAULT_SECURITY_SENSORS.iter().map(|name| (*name).to_owned()).collect(),
            service_tools: DEFAULT_SERVICE_TOOLS.iter().map(|name| (*name).to_owned()).collect(),
            os_vendor_signers: DEFAULT_OS_VENDOR_SIGNERS.iter().map(|name| (*name).to_owned()).collect(),
            critical_asr_rules: vec![LSASS_CREDENTIAL_THEFT_RULE, EXECUTABLE_CONTENT_FROM_EMAIL_RULE, OFFICE_CHILD_PROCESS_RULE],
        }
    }
}


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("`{entry}` is not a canonical path: {form}")]
    InvalidPath { entry: String, form: PathForm },
    #[error("an interpreter name is empty")]
    EmptyInterpreter,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPath {
    pub name: String,
    pub path: CanonicalPath,
}


/// The policy with its paths parsed once, so a bad entry refuses the file instead of silently matching nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicy {
    pub policy: Policy,
    pub hash: String,
    pub writable: Vec<NamedPath>,
    pub protected: Vec<NamedPath>,
    pub os_dirs: Vec<NamedPath>,
    pub segments: Vec<String>,
    pub interpreter_stems: Vec<String>,
    pub sensor_stems: Vec<String>,
    pub tool_stems: Vec<String>,
    pub vendor_signers: Vec<String>,
}


pub fn named_paths(entries: &[String]) -> Result<Vec<NamedPath>, PolicyError> {
    entries
        .iter()
        .map(|entry| {
            canonical_path(entry)
                .map(|path| NamedPath { name: entry.clone(), path })
                .map_err(|form| PolicyError::InvalidPath { entry: entry.clone(), form })
        })
        .collect()
}


/// A name up to its first dot, lowercased: `PowerShell.exe` and `python3.11` give `powershell` and `python3`.
pub fn stem_of(name: &str) -> String {
    name.split('.').next().unwrap_or(name).trim().to_lowercase()
}


pub fn interpreter_stems(names: &[String]) -> Result<Vec<String>, PolicyError> {
    names
        .iter()
        .map(|name| Some(stem_of(name)).filter(|stem| !stem.is_empty()).ok_or(PolicyError::EmptyInterpreter))
        .collect()
}


/// `hash` is the SHA-256 of the exact bytes that were parsed.
pub fn compile(policy: Policy, hash: String) -> Result<LoadedPolicy, PolicyError> {
    let writable = named_paths(&policy.user_writable_prefixes)?;
    let protected_entries: Vec<String> = policy.honeytoken_paths.iter().chain(&policy.agent_paths).cloned().collect();
    let protected = named_paths(&protected_entries)?;
    let os_dirs = named_paths(&policy.os_directories)?;
    let segments = policy.user_writable_segments.iter().map(|segment| segment.to_lowercase()).collect();
    let stems = interpreter_stems(&policy.interpreters)?;
    let sensor_stems = interpreter_stems(&policy.security_sensors)?;
    let tool_stems = interpreter_stems(&policy.service_tools)?;
    let vendor_signers = policy.os_vendor_signers.iter().map(|signer| signer.trim().to_lowercase()).collect();
    Ok(LoadedPolicy {
        policy,
        hash,
        writable,
        protected,
        os_dirs,
        segments,
        interpreter_stems: stems,
        sensor_stems,
        tool_stems,
        vendor_signers,
    })
}


pub fn policy_version(loaded: &LoadedPolicy) -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), loaded.hash)
}
