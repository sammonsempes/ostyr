#![cfg(feature = "ebpf-load")]
//! The production loader: load the exec probe from checked bytes, attach it, drain its ring. Proved by the `ebpf` workflow and the lab only.

use crate::btf::{read_task_offsets, require_64_bit, Unsupported, VMLINUX_BTF_PATH};
use crate::drain::{decode_batch, kernel_dropped, report_of, wait_after, warning_text, DrainReport};
use crate::limiter::Limiter;
use crate::object::{read_object, ObjectError};
use crate::record::ExecRecord;
use aya::maps::{MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::{ProgramError, TracePoint};
use aya::{Ebpf, EbpfError, EbpfLoader};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};


pub const PROGRAM_NAME: &str = "sched_process_exec";


pub const RING_NAME: &str = "EXEC_EVENTS";


pub const DROPS_NAME: &str = "EXEC_DROPS";


pub const NO_PIN_DIRECTORY: &str = "/proc/self/ostyr-no-pin";


const DROP_SLOT: u32 = 0;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    Object(ObjectError),
    Btf(Unsupported),
    Parse,
    MapCreate { errno: Option<i32> },
    Pinned,
    ProgramLoad { errno: Option<i32> },
    Attach { errno: Option<i32> },
    MissingProgram,
    WrongProgramType,
    TakeMap(&'static str),
}


impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Object(error) => write!(formatter, "exec object refused: {error}"),
            LoadError::Btf(error) => write!(formatter, "kernel BTF refused: {error}"),
            LoadError::Parse => write!(formatter, "exec object cannot be parsed"),
            LoadError::MapCreate { errno } => write!(formatter, "exec map cannot be created (errno {errno:?})"),
            LoadError::Pinned => write!(formatter, "exec object declares a pinned map"),
            LoadError::ProgramLoad { errno } => write!(formatter, "exec program cannot be loaded (errno {errno:?})"),
            LoadError::Attach { errno } => write!(formatter, "exec program cannot be attached (errno {errno:?})"),
            LoadError::MissingProgram => write!(formatter, "program {PROGRAM_NAME} is missing"),
            LoadError::WrongProgramType => write!(formatter, "program {PROGRAM_NAME} is not a tracepoint"),
            LoadError::TakeMap(name) => write!(formatter, "map {name} is missing or has the wrong type"),
        }
    }
}


impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Object(error) => Some(error),
            LoadError::Btf(error) => Some(error),
            _ => None,
        }
    }
}


impl From<ObjectError> for LoadError {
    fn from(error: ObjectError) -> Self {
        LoadError::Object(error)
    }
}


impl From<Unsupported> for LoadError {
    fn from(error: Unsupported) -> Self {
        LoadError::Btf(error)
    }
}


pub struct Probe {
    pub ebpf: Ebpf,
    pub ring: RingBuf<MapData>,
    pub drops: PerCpuArray<MapData, u64>,
    pub limiter: Limiter,
    pub baseline: u64,
}


#[derive(Clone, Debug)]
pub struct Drained {
    pub records: Vec<ExecRecord>,
    pub report: DrainReport,
}


fn program_errno(error: &ProgramError) -> Option<i32> {
    match error {
        ProgramError::LoadError { io_error, .. } => io_error.raw_os_error(),
        ProgramError::SyscallError(syscall) => syscall.io_error.raw_os_error(),
        ProgramError::IOError(io_error) => io_error.raw_os_error(),
        _ => None,
    }
}


fn map_error(error: &MapError) -> LoadError {
    match error {
        MapError::PinError { .. } => LoadError::Pinned,
        MapError::CreateError { io_error, .. } => LoadError::MapCreate {
            errno: io_error.raw_os_error(),
        },
        _ => LoadError::MapCreate { errno: None },
    }
}


fn ebpf_error(error: &EbpfError) -> LoadError {
    match error {
        EbpfError::MapError(inner) => map_error(inner),
        EbpfError::ProgramError(inner) => LoadError::ProgramLoad { errno: program_errno(inner) },
        _ => LoadError::Parse,
    }
}


/// Loads the probe from bytes already judged by `read_object`; maps that ask for pinning fail because the pin directory cannot exist.
pub fn load_exec_probe_from_bytes(bytes: &[u8]) -> Result<Probe, LoadError> {
    require_64_bit(usize::BITS)?;
    let offsets = read_task_offsets(Path::new(VMLINUX_BTF_PATH))?;
    let real_parent = u64::from(offsets.real_parent);
    let tgid = u64::from(offsets.tgid);
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(NO_PIN_DIRECTORY)
        .override_global("REAL_PARENT_OFFSET", &real_parent, true)
        .override_global("TGID_OFFSET", &tgid, true)
        .load(bytes)
        .map_err(|error| ebpf_error(&error))?;
    let program: &mut TracePoint = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or(LoadError::MissingProgram)?
        .try_into()
        .map_err(|_| LoadError::WrongProgramType)?;
    program.load().map_err(|error| LoadError::ProgramLoad {
        errno: program_errno(&error),
    })?;
    program.attach("sched", PROGRAM_NAME).map_err(|error| LoadError::Attach {
        errno: program_errno(&error),
    })?;
    let ring = ebpf
        .take_map(RING_NAME)
        .ok_or(LoadError::TakeMap(RING_NAME))
        .and_then(|map| RingBuf::try_from(map).map_err(|_| LoadError::TakeMap(RING_NAME)))?;
    let drops = ebpf
        .take_map(DROPS_NAME)
        .ok_or(LoadError::TakeMap(DROPS_NAME))
        .and_then(|map| PerCpuArray::try_from(map).map_err(|_| LoadError::TakeMap(DROPS_NAME)))?;
    Ok(Probe {
        ebpf,
        ring,
        drops,
        limiter: Limiter::default(),
        baseline: 0,
    })
}


/// Reads the object at `path` through the checked handle, then loads it (production passes `EXEC_OBJECT_PATH`); dropping the probe detaches and closes everything.
pub fn load_exec_probe(path: &Path) -> Result<Probe, LoadError> {
    let bytes = read_object(path)?;
    load_exec_probe_from_bytes(&bytes)
}


/// Sums the one-slot per-CPU drop counter over the CPUs.
pub fn read_dropped(drops: &PerCpuArray<MapData, u64>) -> Result<u64, MapError> {
    let per_cpu = drops.get(&DROP_SLOT, 0)?;
    Ok(per_cpu.iter().fold(0, |sum: u64, value| sum.saturating_add(*value)))
}


/// Drains at most `max_records` without waiting, and logs one warn line when anything was lost, refused or unknown.
pub fn drain_exec(probe: &mut Probe, max_records: usize) -> Drained {
    let ring = &mut probe.ring;
    let mut raw = std::iter::from_fn(|| ring.next().map(|item| item.to_vec()));
    let batch = decode_batch(&mut raw, &mut probe.limiter, max_records);
    let current = read_dropped(&probe.drops)
        .map_err(|_| tracing::warn!("exec drop counter is unreadable"))
        .ok();
    let kernel = kernel_dropped(&mut probe.baseline, current);
    let report = report_of(&batch, max_records, kernel);
    let warning = warning_text(&report);
    if let Some(text) = warning {
        tracing::warn!("{text}");
    }
    Drained {
        records: batch.records,
        report,
    }
}


/// Polls at a fixed interval, at most `max_polls` times or until `stop` is set; `more_pending` never causes an immediate second poll.
pub fn poll_exec(probe: &mut Probe, stop: &AtomicBool, max_polls: u32, max_records: usize, deliver: &mut dyn FnMut(Drained)) -> u32 {
    let polls = (0..max_polls).take_while(|_| !stop.load(Ordering::Relaxed)).map(|_| {
        let drained = drain_exec(probe, max_records);
        let wait = wait_after(&drained.report);
        deliver(drained);
        std::thread::sleep(wait);
    });
    u32::try_from(polls.count()).unwrap_or(u32::MAX)
}
