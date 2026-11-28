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


pub const FILE_PROGRAM_NAME: &str = "security_file_open";


pub const FILE_FUNCTION: &str = "security_file_open";


pub const FILE_RING_NAME: &str = "FILE_EVENTS";


pub const FILE_DROPS_NAME: &str = "FILE_DROPS";


pub const RODATA_NAME: &str = ".rodata";


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachKind {
    TracePoint { category: &'static str, name: &'static str },
    FExit { function: &'static str },
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Exec,
    File,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeSpec {
    pub name: &'static str,
    pub kind: RecordKind,
    pub program: &'static str,
    pub ring: &'static str,
    pub drops: &'static str,
    pub attach: AttachKind,
}


pub const EXEC_PROBE: ProbeSpec = ProbeSpec {
    name: "exec",
    kind: RecordKind::Exec,
    program: PROGRAM_NAME,
    ring: RING_NAME,
    drops: DROPS_NAME,
    attach: AttachKind::TracePoint {
        category: "sched",
        name: PROGRAM_NAME,
    },
};


pub const FILE_PROBE: ProbeSpec = ProbeSpec {
    name: "file",
    kind: RecordKind::File,
    program: FILE_PROGRAM_NAME,
    ring: FILE_RING_NAME,
    drops: FILE_DROPS_NAME,
    attach: AttachKind::FExit { function: FILE_FUNCTION },
};


pub const PROBE_TABLE: [ProbeSpec; 2] = [EXEC_PROBE, FILE_PROBE];


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShapeError {
    Parse,
    PinnedMap,
    ExtraMap,
    MissingMap(&'static str),
    WrongMapType(&'static str),
    ExtraProgram,
    MissingProgram(&'static str),
    WrongProgramType(&'static str),
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
            ShapeError::MissingProgram(name) => write!(formatter, "exec object lacks program {name}"),
            ShapeError::WrongProgramType(name) => write!(formatter, "exec program {name} has the wrong attach type"),
        }
    }
}


impl std::error::Error for ShapeError {}


fn map_type_is(maps: &HashMap<String, Map>, name: &'static str, expected: u32) -> Result<(), ShapeError> {
    let map = maps.get(name).ok_or(ShapeError::MissingMap(name))?;
    (map.map_type() == expected).then_some(()).ok_or(ShapeError::WrongMapType(name))
}


fn section_matches(attach: &AttachKind, section: &ProgramSection) -> bool {
    match attach {
        AttachKind::TracePoint { .. } => matches!(section, ProgramSection::TracePoint),
        AttachKind::FExit { .. } => matches!(section, ProgramSection::FExit { sleepable: false }),
    }
}


fn probe_maps_ok(object: &Object, spec: &ProbeSpec) -> Result<(), ShapeError> {
    map_type_is(&object.maps, spec.ring, BPF_MAP_TYPE_RINGBUF as u32)?;
    map_type_is(&object.maps, spec.drops, BPF_MAP_TYPE_PERCPU_ARRAY as u32)
}


fn probe_program_ok(object: &Object, spec: &ProbeSpec) -> Result<(), ShapeError> {
    let program = object.programs.get(spec.program).ok_or(ShapeError::MissingProgram(spec.program))?;
    section_matches(&spec.attach, &program.section)
        .then_some(())
        .ok_or(ShapeError::WrongProgramType(spec.program))
}


/// Refuses an object unless it holds exactly the maps, the rodata map and the programs of `table`, each program of its attach kind, with no pinning anywhere.
pub fn check_shape_for(object: &Object, table: &[ProbeSpec]) -> Result<(), ShapeError> {
    let unpinned = object.maps.values().all(|map| map.pinning() == PinningType::None);
    unpinned.then_some(()).ok_or(ShapeError::PinnedMap)?;
    let known = object
        .maps
        .keys()
        .all(|name| name == RODATA_NAME || table.iter().any(|spec| spec.ring == name || spec.drops == name));
    known.then_some(()).ok_or(ShapeError::ExtraMap)?;
    table.iter().try_for_each(|spec| probe_maps_ok(object, spec))?;
    let rodata = object.maps.get(RODATA_NAME).ok_or(ShapeError::MissingMap(RODATA_NAME))?;
    let rodata_kind = rodata.section_kind() == EbpfSectionKind::Rodata;
    rodata_kind.then_some(()).ok_or(ShapeError::WrongMapType(RODATA_NAME))?;
    let only_known = object.programs.keys().all(|name| table.iter().any(|spec| spec.program == name));
    only_known.then_some(()).ok_or(ShapeError::ExtraProgram)?;
    table.iter().try_for_each(|spec| probe_program_ok(object, spec))
}


/// Parses the checked bytes with aya's own object parser and judges the result against `table`; these are the bytes aya loads afterwards.
pub fn check_object_bytes_for(bytes: &[u8], table: &[ProbeSpec]) -> Result<(), ShapeError> {
    let object = Object::parse(bytes).map_err(|_| ShapeError::Parse)?;
    check_shape_for(&object, table)
}


/// `check_object_bytes_for` with the production table.
pub fn check_object_bytes(bytes: &[u8]) -> Result<(), ShapeError> {
    check_object_bytes_for(bytes, &PROBE_TABLE)
}
