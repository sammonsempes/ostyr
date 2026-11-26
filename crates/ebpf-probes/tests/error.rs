#![cfg(target_os = "linux")]

use aya::maps::MapError;
use aya::programs::ProgramError;
use aya::sys::SyscallError;
use aya::EbpfError;
use ebpf_probes::btf::Unsupported;
use ebpf_probes::error::{
    attach_error, ebpf_error, errno_of, load_error_name, map_error, program_load_error, settle_probe, split_settled, FileProbeUnavailable, LoadError,
    Settled, OBJECT_PROBE,
};
use ebpf_probes::object::ObjectError;
use ebpf_probes::shape::{ShapeError, DROPS_NAME, EXEC_PROBE, FILE_PROBE, PROGRAM_NAME, RING_NAME};
use std::error::Error;
use std::io;


const MARKER: &str = "MARKER-91c4e0";


const PERMISSION: i32 = 1;


const NO_ACCESS: i32 = 13;


const BUSY: i32 = 16;


const CAUSED_VARIANTS: usize = 3;


fn syscall_error(call: &'static str, errno: i32) -> SyscallError {
    SyscallError {
        call,
        io_error: io::Error::from_raw_os_error(errno),
    }
}


fn chain_texts(error: &LoadError) -> Vec<String> {
    let first: &(dyn Error + 'static) = error;
    std::iter::successors(Some(first), |inner| (*inner).source())
        .flat_map(|inner| [inner.to_string(), format!("{inner:?}")])
        .collect()
}


#[test]
fn the_errno_is_found_on_the_source_chain() -> Result<(), Box<dyn Error>> {
    assert_eq!(errno_of(&io::Error::from_raw_os_error(NO_ACCESS)), Some(NO_ACCESS));
    assert_eq!(errno_of(&io::Error::from(io::ErrorKind::Other)), None);
    assert_eq!(errno_of(&ProgramError::NotLoaded), None);
    assert_eq!(errno_of(&syscall_error("bpf", PERMISSION)), Some(PERMISSION));
    assert_eq!(errno_of(&ProgramError::SyscallError(syscall_error("bpf", BUSY))), Some(BUSY));
    Ok(())
}


#[test]
fn each_aya_step_maps_to_its_own_fixed_variant() -> Result<(), Box<dyn Error>> {
    let created = MapError::CreateError {
        name: MARKER.to_string(),
        io_error: io::Error::from_raw_os_error(PERMISSION),
    };
    assert_eq!(map_error(&created), LoadError::MapCreate { errno: Some(PERMISSION) });
    assert_eq!(map_error(&MapError::KeyNotFound), LoadError::MapCreate { errno: None });
    assert_eq!(
        ebpf_error(&EbpfError::MapError(created)),
        LoadError::MapCreate { errno: Some(PERMISSION) }
    );
    assert_eq!(
        ebpf_error(&EbpfError::ProgramError(ProgramError::SyscallError(syscall_error("bpf", NO_ACCESS)))),
        LoadError::ProgramLoad {
            probe: OBJECT_PROBE,
            errno: Some(NO_ACCESS)
        }
    );
    assert_eq!(ebpf_error(&EbpfError::NoBTF), LoadError::Parse);
    assert_eq!(
        program_load_error(FILE_PROBE.name, &ProgramError::NotLoaded),
        LoadError::ProgramLoad {
            probe: FILE_PROBE.name,
            errno: None
        }
    );
    assert_eq!(
        program_load_error(EXEC_PROBE.name, &syscall_error("bpf", BUSY)),
        LoadError::ProgramLoad {
            probe: EXEC_PROBE.name,
            errno: Some(BUSY)
        }
    );
    assert_eq!(
        attach_error(FILE_PROBE.name, &ProgramError::NotAttached),
        LoadError::Attach {
            probe: FILE_PROBE.name,
            errno: None
        }
    );
    assert_eq!(
        attach_error(EXEC_PROBE.name, &ProgramError::SyscallError(syscall_error("perf", NO_ACCESS))),
        LoadError::Attach {
            probe: EXEC_PROBE.name,
            errno: Some(NO_ACCESS)
        }
    );
    Ok(())
}


#[test]
fn no_aya_error_text_reaches_display_debug_or_a_source() -> Result<(), Box<dyn Error>> {
    let created = EbpfError::MapError(MapError::CreateError {
        name: MARKER.to_string(),
        io_error: io::Error::other(MARKER),
    });
    let marked = [
        ebpf_error(&created),
        program_load_error(FILE_PROBE.name, &io::Error::other(MARKER)),
        attach_error(FILE_PROBE.name, &io::Error::other(MARKER)),
        ebpf_error(&EbpfError::ProgramError(ProgramError::UnknownInterface {
            name: std::ffi::CString::new(MARKER)?,
        })),
    ];
    marked.iter().for_each(|error| {
        assert!(chain_texts(error).iter().all(|text| !text.contains(MARKER)), "{error:?}");
        assert!(Error::source(error).is_none());
    });
    Ok(())
}


#[test]
fn every_variant_has_fixed_text_and_the_inner_causes_are_kept() -> Result<(), Box<dyn Error>> {
    let unsupported = Unsupported("no task_struct");
    let all = [
        LoadError::from(ObjectError::Owner),
        LoadError::from(ShapeError::PinnedMap),
        LoadError::from(unsupported),
        LoadError::Parse,
        LoadError::MapCreate { errno: Some(1) },
        LoadError::ProgramLoad {
            probe: EXEC_PROBE.name,
            errno: None,
        },
        LoadError::Attach {
            probe: EXEC_PROBE.name,
            errno: Some(NO_ACCESS),
        },
        LoadError::MissingProgram(PROGRAM_NAME),
        LoadError::WrongProgramType(PROGRAM_NAME),
        LoadError::TakeMap(RING_NAME),
        LoadError::TakeMap(DROPS_NAME),
        LoadError::NotBuilt,
    ];
    let texts: Vec<String> = all.iter().map(ToString::to_string).collect();
    assert_eq!(texts.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
    assert!(texts
        .iter()
        .all(|text| text.starts_with("exec ") || text.starts_with("kernel ") || text.starts_with("program ") || text.starts_with("map ")));
    let with_source: Vec<bool> = all.iter().map(|error| Error::source(error).is_some()).collect();
    assert!(with_source.iter().take(CAUSED_VARIANTS).all(|has| *has));
    assert!(with_source.iter().skip(CAUSED_VARIANTS).all(|has| !has));
    assert_eq!(all.first(), Some(&LoadError::Object(ObjectError::Owner)));
    Ok(())
}


#[test]
fn every_variant_has_one_fixed_name_without_errno_or_cause() -> Result<(), Box<dyn Error>> {
    let all = [
        LoadError::from(ObjectError::Owner),
        LoadError::from(ShapeError::PinnedMap),
        LoadError::from(Unsupported("no task_struct")),
        LoadError::Parse,
        LoadError::MapCreate { errno: Some(1) },
        LoadError::ProgramLoad {
            probe: EXEC_PROBE.name,
            errno: Some(NO_ACCESS),
        },
        LoadError::Attach {
            probe: EXEC_PROBE.name,
            errno: None,
        },
        LoadError::MissingProgram(PROGRAM_NAME),
        LoadError::WrongProgramType(PROGRAM_NAME),
        LoadError::TakeMap(RING_NAME),
        LoadError::NotBuilt,
    ];
    let names: Vec<&str> = all.iter().map(load_error_name).collect();
    assert_eq!(
        names,
        [
            "Object",
            "Shape",
            "Btf",
            "Parse",
            "MapCreate",
            "ProgramLoad",
            "Attach",
            "MissingProgram",
            "WrongProgramType",
            "TakeMap",
            "NotBuilt"
        ]
    );
    Ok(())
}


#[test]
fn load_and_attach_errors_name_the_probe() -> Result<(), Box<dyn Error>> {
    let loaded = program_load_error(FILE_PROBE.name, &ProgramError::NotLoaded).to_string();
    let attached = attach_error(FILE_PROBE.name, &ProgramError::NotAttached).to_string();
    assert!(loaded.contains(FILE_PROBE.name), "{loaded}");
    assert!(attached.contains(FILE_PROBE.name), "{attached}");
    assert!(!loaded.contains(EXEC_PROBE.name) && !attached.contains(EXEC_PROBE.name));
    Ok(())
}


#[test]
fn a_failing_file_probe_is_named_and_a_failing_exec_probe_is_the_whole_failure() -> Result<(), Box<dyn Error>> {
    let refused = program_load_error(FILE_PROBE.name, &ProgramError::NotLoaded);
    let optional = settle_probe::<&str>(&FILE_PROBE, Err(refused))?;
    let expected = FileProbeUnavailable {
        probe: FILE_PROBE.name,
        reason: refused,
    };
    assert_eq!(optional, Settled::Unavailable(expected));
    assert!(expected.to_string().contains(FILE_PROBE.name));
    let required = program_load_error(EXEC_PROBE.name, &ProgramError::NotLoaded);
    assert_eq!(settle_probe::<&str>(&EXEC_PROBE, Err(required)), Err(required));
    assert_eq!(settle_probe(&EXEC_PROBE, Ok("a"))?, Settled::Ready("a"));
    assert_eq!(settle_probe(&FILE_PROBE, Ok("b"))?, Settled::Ready("b"));
    Ok(())
}


#[test]
fn settled_steps_split_into_ready_states_and_named_losses_in_order() -> Result<(), Box<dyn Error>> {
    let lost = FileProbeUnavailable {
        probe: FILE_PROBE.name,
        reason: LoadError::NotBuilt,
    };
    let (ready, unavailable) = split_settled(vec![Settled::Ready("a"), Settled::Unavailable(lost), Settled::Ready("b")]);
    assert_eq!(ready, ["a", "b"]);
    assert_eq!(unavailable, [lost]);
    Ok(())
}
