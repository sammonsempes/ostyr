#![cfg(target_os = "linux")]
//! Load errors of the exec probe: one fixed variant per step, keeping only an errno, never an aya error or its text.

use crate::btf::Unsupported;
use crate::object::ObjectError;
use crate::shape::{ProbeSpec, RecordKind, ShapeError};
use aya::maps::MapError;
use aya::EbpfError;
use std::fmt;
use std::io;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    Object(ObjectError),
    Shape(ShapeError),
    Btf(Unsupported),
    Parse,
    MapCreate { errno: Option<i32> },
    ProgramLoad { probe: &'static str, errno: Option<i32> },
    Attach { probe: &'static str, errno: Option<i32> },
    MissingProgram(&'static str),
    WrongProgramType(&'static str),
    TakeMap(&'static str),
    NotBuilt,
}


impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Object(error) => write!(formatter, "exec object refused: {error}"),
            LoadError::Shape(error) => write!(formatter, "exec object shape refused: {error}"),
            LoadError::Btf(error) => write!(formatter, "kernel BTF refused: {error}"),
            LoadError::Parse => write!(formatter, "exec object cannot be loaded"),
            LoadError::MapCreate { errno } => write!(formatter, "exec map cannot be created (errno {errno:?})"),
            LoadError::ProgramLoad { probe, errno } => write!(formatter, "{probe} program cannot be loaded (errno {errno:?})"),
            LoadError::Attach { probe, errno } => write!(formatter, "{probe} program cannot be attached (errno {errno:?})"),
            LoadError::MissingProgram(name) => write!(formatter, "program {name} is missing"),
            LoadError::WrongProgramType(name) => write!(formatter, "program {name} has the wrong attach type"),
            LoadError::TakeMap(name) => write!(formatter, "map {name} is missing or has the wrong type"),
            LoadError::NotBuilt => write!(formatter, "exec probe is not built into this agent"),
        }
    }
}


impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Object(error) => Some(error),
            LoadError::Shape(error) => Some(error),
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


impl From<ShapeError> for LoadError {
    fn from(error: ShapeError) -> Self {
        LoadError::Shape(error)
    }
}


impl From<Unsupported> for LoadError {
    fn from(error: Unsupported) -> Self {
        LoadError::Btf(error)
    }
}


/// The errno of the first `io::Error` on the source chain, or none.
pub fn errno_of(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    std::iter::successors(Some(error), |inner| inner.source()).find_map(|inner| inner.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error))
}


/// A map creation failure keeps its errno; any other map error has none.
pub fn map_error(error: &MapError) -> LoadError {
    LoadError::MapCreate { errno: errno_of(error) }
}


/// Maps the error of `EbpfLoader::load` to the step that failed.
pub fn ebpf_error(error: &EbpfError) -> LoadError {
    match error {
        EbpfError::MapError(inner) => map_error(inner),
        EbpfError::ProgramError(inner) => LoadError::ProgramLoad {
            probe: OBJECT_PROBE,
            errno: errno_of(inner),
        },
        _ => LoadError::Parse,
    }
}


/// A program load failure names the probe and keeps its errno.
pub fn program_load_error(probe: &'static str, error: &(dyn std::error::Error + 'static)) -> LoadError {
    LoadError::ProgramLoad {
        probe,
        errno: errno_of(error),
    }
}


/// An attach failure names the probe and keeps its errno.
pub fn attach_error(probe: &'static str, error: &(dyn std::error::Error + 'static)) -> LoadError {
    LoadError::Attach {
        probe,
        errno: errno_of(error),
    }
}


/// The probe name of an error raised by the object as a whole, before any one probe is loaded.
pub const OBJECT_PROBE: &str = "object";


/// An optional probe that could not be loaded or attached: exec keeps running, the caller logs this at error level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileProbeUnavailable {
    pub probe: &'static str,
    pub reason: LoadError,
}


impl fmt::Display for FileProbeUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "probe {} is unavailable: {}", self.probe, self.reason)
    }
}


/// One step of one probe: it worked, or it was optional and failed.
#[derive(Debug, Eq, PartialEq)]
pub enum Settled<State> {
    Ready(State),
    Unavailable(FileProbeUnavailable),
}


/// A required probe (the exec probe) keeps its failure as the whole failure; any other probe turns it into a named `FileProbeUnavailable`.
pub fn settle_probe<State>(spec: &ProbeSpec, result: Result<State, LoadError>) -> Result<Settled<State>, LoadError> {
    match result {
        Ok(state) => Ok(Settled::Ready(state)),
        Err(reason) if spec.kind == RecordKind::Exec => Err(reason),
        Err(reason) => Ok(Settled::Unavailable(FileProbeUnavailable { probe: spec.name, reason })),
    }
}


/// Splits settled steps into the ready states and the unavailable probes, each in order.
pub fn split_settled<State>(settled: Vec<Settled<State>>) -> (Vec<State>, Vec<FileProbeUnavailable>) {
    settled.into_iter().fold((Vec::new(), Vec::new()), |(mut ready, mut lost), step| {
        match step {
            Settled::Ready(state) => ready.push(state),
            Settled::Unavailable(unavailable) => lost.push(unavailable),
        }
        (ready, lost)
    })
}


/// The fixed variant name of a load error, for audit records; never an errno, a path or any text of the cause.
pub fn load_error_name(error: &LoadError) -> &'static str {
    match error {
        LoadError::Object(_) => "Object",
        LoadError::Shape(_) => "Shape",
        LoadError::Btf(_) => "Btf",
        LoadError::Parse => "Parse",
        LoadError::MapCreate { .. } => "MapCreate",
        LoadError::ProgramLoad { .. } => "ProgramLoad",
        LoadError::Attach { .. } => "Attach",
        LoadError::MissingProgram(_) => "MissingProgram",
        LoadError::WrongProgramType(_) => "WrongProgramType",
        LoadError::TakeMap(_) => "TakeMap",
        LoadError::NotBuilt => "NotBuilt",
    }
}
