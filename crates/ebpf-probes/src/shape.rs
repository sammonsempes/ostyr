#![cfg(target_os = "linux")]
//! Judges the parsed exec object before aya loads it: the two maps, the rodata map and the one tracepoint program, none pinned.

use aya_obj::generated::bpf_map_type::{BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF};
use aya_obj::maps::PinningType;
use aya_obj::{EbpfSectionKind, Map, Object, ProgramSection};
use std::collections::HashMap;
use std::fmt;


pub const PROGRAM_NAME: &str = "sched_process_exec";


pub const RING_NAME: &str = "EXEC_EVENTS";


pub const DROPS_NAME: &str = "EXEC_DROPS";


pub const RODATA_NAME: &str = ".rodata";


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShapeError {
    Parse,
    PinnedMap,
    ExtraMap,
    MissingMap(&'static str),
    WrongMapType(&'static str),
    ExtraProgram,
    MissingProgram,
    WrongProgramType,
}


impl fmt::Display for ShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShapeError::Parse => write!(formatter, "exec object cannot be parsed"),
            ShapeError::PinnedMap => write!(formatter, "exec object declares a pinned map"),
            ShapeError::ExtraMap => write!(formatter, "exec object holds a map that is not expected"),
            ShapeError::MissingMap(name) => write!(formatter, "exec object lacks map {name}"),
            ShapeError::WrongMapType(name) => write!(formatter, "exec map {name} has the wrong type"),
            ShapeError::ExtraProgram => write!(formatter, "exec object holds a program that is not expected"),
            ShapeError::MissingProgram => write!(formatter, "exec object lacks program {PROGRAM_NAME}"),
            ShapeError::WrongProgramType => write!(formatter, "exec program {PROGRAM_NAME} is not a tracepoint"),
        }
    }
}


impl std::error::Error for ShapeError {}


fn map_type_is(maps: &HashMap<String, Map>, name: &'static str, expected: u32) -> Result<(), ShapeError> {
    let map = maps.get(name).ok_or(ShapeError::MissingMap(name))?;
    (map.map_type() == expected).then_some(()).ok_or(ShapeError::WrongMapType(name))
}


/// Refuses an object unless it holds exactly the two exec maps, the rodata map and the one tracepoint program, with no pinning anywhere.
pub fn check_shape(object: &Object) -> Result<(), ShapeError> {
    let unpinned = object.maps.values().all(|map| map.pinning() == PinningType::None);
    unpinned.then_some(()).ok_or(ShapeError::PinnedMap)?;
    let expected = [RING_NAME, DROPS_NAME, RODATA_NAME];
    let known = object.maps.keys().all(|name| expected.contains(&name.as_str()));
    known.then_some(()).ok_or(ShapeError::ExtraMap)?;
    map_type_is(&object.maps, RING_NAME, BPF_MAP_TYPE_RINGBUF as u32)?;
    map_type_is(&object.maps, DROPS_NAME, BPF_MAP_TYPE_PERCPU_ARRAY as u32)?;
    let rodata = object.maps.get(RODATA_NAME).ok_or(ShapeError::MissingMap(RODATA_NAME))?;
    let rodata_kind = rodata.section_kind() == EbpfSectionKind::Rodata;
    rodata_kind.then_some(()).ok_or(ShapeError::WrongMapType(RODATA_NAME))?;
    let only_program = object.programs.keys().all(|name| name == PROGRAM_NAME);
    only_program.then_some(()).ok_or(ShapeError::ExtraProgram)?;
    let program = object.programs.get(PROGRAM_NAME).ok_or(ShapeError::MissingProgram)?;
    let tracepoint = matches!(program.section, ProgramSection::TracePoint);
    tracepoint.then_some(()).ok_or(ShapeError::WrongProgramType)
}


/// Parses the checked bytes with aya's own object parser and judges the result; these are the bytes aya loads afterwards.
pub fn check_object_bytes(bytes: &[u8]) -> Result<(), ShapeError> {
    let object = Object::parse(bytes).map_err(|_| ShapeError::Parse)?;
    check_shape(&object)
}
