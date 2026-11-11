use crate::error::{CapabilityError, SourceError};
use crate::spool::append_locked;
use crate::types::ReadFn;
use crate::types::SpoolLock;
use flate2::read::GzDecoder;
use serde_json::json;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read};
use std::iter::once;
use std::path::Path;


/// Root of the real system; tests pass a temporary tree instead.
pub const SYSTEM_ROOT: &str = "/";


/// Cap for the small files (kernel release, LSM list).
pub const MAX_SMALL_BYTES: u64 = 4096;


/// Cap for the kernel config, compressed or not.
pub const MAX_CONFIG_BYTES: u64 = 16_777_216;


pub const OSRELEASE_FILE: &str = "proc/sys/kernel/osrelease";


pub const CONFIG_GZ_FILE: &str = "proc/config.gz";


pub const LSM_FILE: &str = "sys/kernel/security/lsm";


pub const BTF_FILE: &str = "sys/kernel/btf/vmlinux";


pub const OPTION_KPROBE_OVERRIDE: &str = "CONFIG_BPF_KPROBE_OVERRIDE";


pub const OPTION_BPF_LSM: &str = "CONFIG_BPF_LSM";


pub const LSM_BPF: &str = "bpf";


/// Oldest kernel for a reduced mode (spec §5, §18).
pub const MIN_REDUCED: KernelVersion = KernelVersion { major: 4, minor: 18 };


/// Oldest kernel for the full mode (spec §5, §18).
pub const MIN_FULL: KernelVersion = KernelVersion { major: 5, minor: 4 };


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Knowledge {
    Yes,
    No,
    Unknown,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub kernel: Option<KernelVersion>,
    pub kprobe_override: Knowledge,
    pub bpf_lsm_config: Knowledge,
    pub bpf_lsm_active: Knowledge,
    pub btf: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Kernel,
    Btf,
    KprobeOverride,
    BpfLsm,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Full(Vec<Missing>),
    Reduced(Vec<Missing>),
    Degraded(Vec<Missing>),
}


impl Display for Missing {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let name = match self {
            Missing::Kernel => "kernel",
            Missing::Btf => "btf",
            Missing::KprobeOverride => "kprobe_override",
            Missing::BpfLsm => "bpf_lsm",
        };
        formatter.write_str(name)
    }
}


impl Display for Mode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let name = match self {
            Mode::Full(_) => "full",
            Mode::Reduced(_) => "reduced",
            Mode::Degraded(_) => "degraded",
        };
        formatter.write_str(name)
    }
}


/// The capabilities a mode reports as missing.
pub fn missing_of(mode: &Mode) -> &[Missing] {
    match mode {
        Mode::Full(missing) | Mode::Reduced(missing) | Mode::Degraded(missing) => missing,
    }
}


/// The missing capabilities of a mode as display names.
pub fn missing_names(mode: &Mode) -> Vec<String> {
    missing_of(mode).iter().map(ToString::to_string).collect()
}


/// Reads at most `cap` bytes of the file: `None` when it is absent, `TooLarge` when it holds more.
pub fn read_bounded(path: &Path, cap: u64) -> Result<Option<Vec<u8>>, CapabilityError> {
    match File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(cap + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > cap {
                Err(CapabilityError::TooLarge(path.to_path_buf(), cap))
            } else {
                Ok(Some(bytes))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}


/// A failed read is logged and counts as unknown.
pub fn settle(outcome: Result<Option<Vec<u8>>, CapabilityError>) -> Option<Vec<u8>> {
    outcome.unwrap_or_else(|error| {
        tracing::warn!(%error, "capability file unusable, treated as unknown");
        None
    })
}


pub fn read_text(root: &Path, relative: &str, read: ReadFn, cap: u64) -> Option<String> {
    settle(read(&root.join(relative), cap)).and_then(|bytes| {
        String::from_utf8(bytes)
            .inspect_err(|error| tracing::warn!(%error, relative, "capability file is not UTF-8, treated as unknown"))
            .ok()
    })
}


/// The compressed file is read under the cap and so is its decompressed text.
pub fn read_gz_text(root: &Path, relative: &str, read: ReadFn) -> Option<String> {
    settle(read(&root.join(relative), MAX_CONFIG_BYTES)).and_then(|bytes| {
        let mut text = String::new();
        let read_ok = GzDecoder::new(bytes.as_slice())
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .inspect_err(|error| tracing::warn!(%error, relative, "kernel config unreadable, treated as unknown"))
            .is_ok();
        let bounded = text.len() as u64 <= MAX_CONFIG_BYTES;
        (read_ok && bounded).then_some(text)
    })
}


/// `major.minor` of a kernel release such as `5.15.0-91-generic` or `4.18.0-553.el8_10.x86_64`.
pub fn parse_release(release: &str) -> Option<KernelVersion> {
    let mut parts = release.trim().split('.');
    let major = leading_number(parts.next()?)?;
    let minor = leading_number(parts.next()?)?;
    Some(KernelVersion { major, minor })
}


pub fn leading_number(text: &str) -> Option<u32> {
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}


pub fn config_option(config: Option<&str>, name: &str) -> Knowledge {
    let enabled = format!("{name}=y");
    config.map_or(Knowledge::Unknown, |text| {
        if text.lines().any(|line| line.trim() == enabled) {
            Knowledge::Yes
        } else {
            Knowledge::No
        }
    })
}


pub fn lsm_state(list: Option<&str>) -> Knowledge {
    list.map_or(Knowledge::Unknown, |text| {
        if text.trim().split(',').any(|name| name == LSM_BPF) {
            Knowledge::Yes
        } else {
            Knowledge::No
        }
    })
}


/// Presence of the BTF file; a check that fails is logged and counts as absent.
pub fn btf_present(root: &Path) -> bool {
    root.join(BTF_FILE).try_exists().unwrap_or_else(|error| {
        tracing::warn!(%error, "BTF presence unknown, treated as absent");
        false
    })
}


/// Measures the system under `root` through `read`; nothing here stops the agent, an unreadable file is unknown.
pub fn detect(root: &Path, read: ReadFn) -> Capabilities {
    let release = read_text(root, OSRELEASE_FILE, read, MAX_SMALL_BYTES).filter(|text| !text.contains('/'));
    let release_name = release.as_deref().map(str::trim);
    let plain = release_name.and_then(|name| read_text(root, &format!("boot/config-{name}"), read, MAX_CONFIG_BYTES));
    let config = plain.or_else(|| read_gz_text(root, CONFIG_GZ_FILE, read));
    let lsm = read_text(root, LSM_FILE, read, MAX_SMALL_BYTES);
    Capabilities {
        kernel: release_name.and_then(parse_release),
        kprobe_override: config_option(config.as_deref(), OPTION_KPROBE_OVERRIDE),
        bpf_lsm_config: config_option(config.as_deref(), OPTION_BPF_LSM),
        bpf_lsm_active: lsm_state(lsm.as_deref()),
        btf: btf_present(root),
    }
}


/// Every capability that is not confirmed present (an unknown one counts as missing).
pub fn missing_list(capabilities: &Capabilities) -> Vec<Missing> {
    [
        (!capabilities.btf, Missing::Btf),
        (capabilities.kprobe_override != Knowledge::Yes, Missing::KprobeOverride),
        (capabilities.bpf_lsm_active != Knowledge::Yes, Missing::BpfLsm),
    ]
    .into_iter()
    .filter_map(|(absent, capability)| absent.then_some(capability))
    .collect()
}


/// Spec §5 and §18: full, reduced or degraded from the kernel, BTF and the enforcement paths.
pub fn effective_mode(capabilities: &Capabilities) -> Mode {
    let missing = missing_list(capabilities);
    let enforcing = capabilities.kprobe_override == Knowledge::Yes || capabilities.bpf_lsm_active == Knowledge::Yes;
    match capabilities.kernel {
        Some(kernel) if kernel >= MIN_FULL && !capabilities.btf => Mode::Degraded(missing),
        Some(kernel) if kernel >= MIN_FULL && enforcing => Mode::Full(missing),
        Some(kernel) if kernel >= MIN_REDUCED => Mode::Reduced(missing),
        _ => Mode::Degraded(vec![Missing::Kernel]),
    }
}


/// The agent-channel event spooled at start (kind `agent.capabilities`).
pub fn capabilities_event(capabilities: &Capabilities, mode: &Mode, measured_at: u64) -> String {
    let kernel = capabilities
        .kernel
        .map_or_else(|| "unknown".to_string(), |version| format!("{}.{}", version.major, version.minor));
    json!({
        "event": {"kind": "agent.capabilities"},
        "agent": {"capabilities": {
            "mode": mode.to_string(),
            "missing": missing_names(mode),
            "kernel": kernel,
            "btf": capabilities.btf,
            "kprobe_override": format!("{:?}", capabilities.kprobe_override),
            "bpf_lsm_config": format!("{:?}", capabilities.bpf_lsm_config),
            "bpf_lsm_active": format!("{:?}", capabilities.bpf_lsm_active),
            "measured_at": measured_at,
        }},
    })
    .to_string()
}


/// Measures, logs the mode once and spools the event; a spool failure is an error, a missing capability is not.
pub fn announce(root: &Path, spool: &Path, lock: &SpoolLock, read: ReadFn, measured_at: u64) -> Result<Mode, SourceError> {
    let capabilities = detect(root, read);
    let mode = effective_mode(&capabilities);
    let missing = missing_names(&mode);
    let mode_name = mode.to_string();
    tracing::info!(mode = %mode_name, missing = ?missing, "effective mode");
    append_locked(lock, once(Ok(capabilities_event(&capabilities, &mode, measured_at))), spool)?;
    Ok(mode)
}
