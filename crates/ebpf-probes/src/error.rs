#![cfg(target_os = "linux")]
//! Load errors of the exec probe: one fixed variant per step, keeping only an errno, never an aya error or its text.

use crate::btf::Unsupported;
use crate::object::ObjectError;
use crate::shape::ShapeError;
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
    ProgramLoad { errno: Option<i32> },
    Attach { errno: Option<i32> },
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
            LoadError::ProgramLoad { errno } => write!(formatter, "exec program cannot be loaded (errno {errno:?})"),
            LoadError::Attach { errno } => write!(formatter, "exec program cannot be attached (errno {errno:?})"),
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
        EbpfError::ProgramError(inner) => LoadError::ProgramLoad { errno: errno_of(inner) },
        _ => LoadError::Parse,
    }
}


/// A program load failure keeps its errno.
pub fn program_load_error(error: &(dyn std::error::Error + 'static)) -> LoadError {
    LoadError::ProgramLoad { errno: errno_of(error) }
}


/// An attach failure keeps its errno.
pub fn attach_error(error: &(dyn std::error::Error + 'static)) -> LoadError {
    LoadError::Attach { errno: errno_of(error) }
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
