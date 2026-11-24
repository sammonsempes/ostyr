#![cfg(target_os = "linux")]

use ebpf_probes::shape::{check_object_bytes, ShapeError, DROPS_NAME, PROGRAM_NAME, RING_NAME, RODATA_NAME};
use std::error::Error;


const ELF_HEADER_BYTES: usize = 64;


const SECTION_HEADER_BYTES: usize = 64;


const SYMBOL_BYTES: usize = 24;


const MAP_DEFINITION_BYTES: usize = 28;


const MACHINE_BPF: u16 = 247;


const TYPE_RELOCATABLE: u16 = 1;


const SECTION_PROGBITS: u32 = 1;


const SECTION_SYMTAB: u32 = 2;


const SECTION_STRTAB: u32 = 3;


const SYMBOL_OBJECT_GLOBAL: u8 = 0x11;


const SYMBOL_FUNCTION_GLOBAL: u8 = 0x12;


const ELF_CLASS_64: u8 = 2;


const ELF_LITTLE_ENDIAN: u8 = 1;


const ELF_CURRENT: u8 = 1;


const IDENT_BYTES: usize = 16;


const MAP_TYPE_RINGBUF: u32 = 27;


const MAP_TYPE_PERCPU_ARRAY: u32 = 6;


const MAP_TYPE_HASH: u32 = 1;


const PIN_BY_NAME: u32 = 1;


const FLAGS_CODE: u64 = 6;


const KEY_BYTES: u32 = 4;


const VALUE_BYTES: u32 = 8;


const ELF_MAGIC_FIRST: u8 = 0x7f;


const PROGRAM_BYTES: usize = 16;


const RODATA_BYTES: usize = 16;


const EXIT_INSTRUCTIONS: [u8; PROGRAM_BYTES] = [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];


const TRACEPOINT_SECTION: &str = "tracepoint/sched/sched_process_exec";


const PIN_PATH_RING: &str = "/sys/fs/bpf/t693as_ring";


const PIN_PATH_DROPS: &str = "/sys/fs/bpf/t693as_drops";


const MARKER: &str = "MARKER-5d2e81";


const LAST_SHORT_LENGTH: usize = 40;


struct Section {
    name: String,
    kind: u32,
    flags: u64,
    data: Vec<u8>,
    link: u32,
    info: u32,
    entry_size: u64,
}


struct Symbol {
    name: String,
    info: u8,
    section: u16,
    size: u64,
    value: u64,
}


struct Spec {
    maps: Vec<(String, u32, u32)>,
    programs: Vec<(String, String)>,
    rodata: bool,
}


fn good_spec() -> Spec {
    Spec {
        maps: vec![
            (RING_NAME.to_string(), MAP_TYPE_RINGBUF, 0),
            (DROPS_NAME.to_string(), MAP_TYPE_PERCPU_ARRAY, 0),
        ],
        programs: vec![(TRACEPOINT_SECTION.to_string(), PROGRAM_NAME.to_string())],
        rodata: true,
    }
}


fn add_name(table: &mut Vec<u8>, name: &str) -> u32 {
    let offset = u32::try_from(table.len()).unwrap_or(0);
    table.extend_from_slice(name.as_bytes());
    table.push(0);
    offset
}


fn section_index(position: usize) -> Result<u16, Box<dyn Error>> {
    Ok(u16::try_from(position + 1)?)
}


fn user_sections(spec: &Spec) -> (Vec<Section>, Vec<Symbol>) {
    let mut sections = vec![Section {
        name: "license".to_string(),
        kind: SECTION_PROGBITS,
        flags: 0,
        data: b"GPL\0".to_vec(),
        link: 0,
        info: 0,
        entry_size: 0,
    }];
    let mut symbols = Vec::new();
    spec.programs.iter().for_each(|(section_name, function)| {
        sections.push(Section {
            name: section_name.clone(),
            kind: SECTION_PROGBITS,
            flags: FLAGS_CODE,
            data: EXIT_INSTRUCTIONS.to_vec(),
            link: 0,
            info: 0,
            entry_size: 0,
        });
        symbols.push(Symbol {
            name: function.clone(),
            info: SYMBOL_FUNCTION_GLOBAL,
            section: u16::try_from(sections.len()).unwrap_or(0),
            size: PROGRAM_BYTES as u64,
            value: 0,
        });
    });
    let mut definitions = Vec::new();
    spec.maps.iter().enumerate().for_each(|(index, (name, map_type, pinning))| {
        let words = [*map_type, KEY_BYTES, VALUE_BYTES, 1, 0, 0, *pinning];
        words.iter().for_each(|word| definitions.extend_from_slice(&word.to_le_bytes()));
        symbols.push(Symbol {
            name: name.clone(),
            info: SYMBOL_OBJECT_GLOBAL,
            section: u16::try_from(sections.len() + 1).unwrap_or(0),
            size: MAP_DEFINITION_BYTES as u64,
            value: (index * MAP_DEFINITION_BYTES) as u64,
        });
    });
    sections.push(Section {
        name: "maps".to_string(),
        kind: SECTION_PROGBITS,
        flags: 0,
        data: definitions,
        link: 0,
        info: 0,
        entry_size: 0,
    });
    spec.rodata.then(|| {
        sections.push(Section {
            name: ".rodata".to_string(),
            kind: SECTION_PROGBITS,
            flags: 0,
            data: vec![0; RODATA_BYTES],
            link: 0,
            info: 0,
            entry_size: 0,
        });
    });
    (sections, symbols)
}


fn push_section_header(out: &mut Vec<u8>, name: u32, section: &Section, offset: u64) {
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&section.kind.to_le_bytes());
    out.extend_from_slice(&section.flags.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(section.data.len() as u64).to_le_bytes());
    out.extend_from_slice(&section.link.to_le_bytes());
    out.extend_from_slice(&section.info.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&section.entry_size.to_le_bytes());
}


fn elf_of(spec: &Spec) -> Result<Vec<u8>, Box<dyn Error>> {
    let (mut sections, symbols) = user_sections(spec);
    let mut strtab = vec![0];
    let mut symtab = vec![0; SYMBOL_BYTES];
    symbols.iter().for_each(|symbol| {
        let name = add_name(&mut strtab, &symbol.name);
        symtab.extend_from_slice(&name.to_le_bytes());
        symtab.push(symbol.info);
        symtab.push(0);
        symtab.extend_from_slice(&symbol.section.to_le_bytes());
        symtab.extend_from_slice(&symbol.value.to_le_bytes());
        symtab.extend_from_slice(&symbol.size.to_le_bytes());
    });
    let strtab_index = u32::from(section_index(sections.len() + 1)?);
    sections.push(Section {
        name: ".symtab".to_string(),
        kind: SECTION_SYMTAB,
        flags: 0,
        data: symtab,
        link: strtab_index,
        info: 1,
        entry_size: SYMBOL_BYTES as u64,
    });
    sections.push(Section {
        name: ".strtab".to_string(),
        kind: SECTION_STRTAB,
        flags: 0,
        data: strtab,
        link: 0,
        info: 0,
        entry_size: 0,
    });
    let mut shstrtab = vec![0];
    let names: Vec<u32> = sections.iter().map(|section| add_name(&mut shstrtab, &section.name)).collect();
    let shstrtab_name = add_name(&mut shstrtab, ".shstrtab");
    sections.push(Section {
        name: ".shstrtab".to_string(),
        kind: SECTION_STRTAB,
        flags: 0,
        data: shstrtab,
        link: 0,
        info: 0,
        entry_size: 0,
    });
    let mut body = Vec::new();
    let offsets: Vec<u64> = sections
        .iter()
        .map(|section| {
            let offset = (ELF_HEADER_BYTES + body.len()) as u64;
            body.extend_from_slice(&section.data);
            offset
        })
        .collect();
    let header_offset = (ELF_HEADER_BYTES + body.len()) as u64;
    let mut out = vec![ELF_MAGIC_FIRST, b'E', b'L', b'F', ELF_CLASS_64, ELF_LITTLE_ENDIAN, ELF_CURRENT];
    out.resize(IDENT_BYTES, 0);
    out.extend_from_slice(&TYPE_RELOCATABLE.to_le_bytes());
    out.extend_from_slice(&MACHINE_BPF.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&header_offset.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(ELF_HEADER_BYTES as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(SECTION_HEADER_BYTES as u16).to_le_bytes());
    out.extend_from_slice(&u16::try_from(sections.len() + 1)?.to_le_bytes());
    out.extend_from_slice(&section_index(sections.len() - 1)?.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&[0; SECTION_HEADER_BYTES]);
    let all_names: Vec<u32> = names.iter().copied().chain(std::iter::once(shstrtab_name)).collect();
    sections
        .iter()
        .zip(all_names.iter().zip(offsets.iter()))
        .for_each(|(section, (name, offset))| push_section_header(&mut out, *name, section, *offset));
    Ok(out)
}


fn verdict(spec: &Spec) -> Result<Result<(), ShapeError>, Box<dyn Error>> {
    Ok(check_object_bytes(&elf_of(spec)?))
}


#[test]
fn the_expected_object_passes() -> Result<(), Box<dyn Error>> {
    assert_eq!(verdict(&good_spec())?, Ok(()));
    Ok(())
}


#[test]
fn a_pinned_map_is_refused_whatever_its_name() -> Result<(), Box<dyn Error>> {
    let mut pinned = good_spec();
    pinned.maps = vec![
        (RING_NAME.to_string(), MAP_TYPE_RINGBUF, PIN_BY_NAME),
        (DROPS_NAME.to_string(), MAP_TYPE_PERCPU_ARRAY, 0),
    ];
    assert_eq!(verdict(&pinned)?, Err(ShapeError::PinnedMap));
    let mut absolute = good_spec();
    absolute.maps = vec![
        (PIN_PATH_RING.to_string(), MAP_TYPE_RINGBUF, PIN_BY_NAME),
        (PIN_PATH_DROPS.to_string(), MAP_TYPE_PERCPU_ARRAY, PIN_BY_NAME),
    ];
    assert_eq!(verdict(&absolute)?, Err(ShapeError::PinnedMap));
    let mut extra_pinned = good_spec();
    extra_pinned.maps.push(("OTHER".to_string(), MAP_TYPE_HASH, PIN_BY_NAME));
    assert_eq!(verdict(&extra_pinned)?, Err(ShapeError::PinnedMap));
    Ok(())
}


#[test]
fn an_unpinned_map_outside_the_allowlist_is_refused() -> Result<(), Box<dyn Error>> {
    let mut extra = good_spec();
    extra.maps.push(("OTHER".to_string(), MAP_TYPE_HASH, 0));
    assert_eq!(verdict(&extra)?, Err(ShapeError::ExtraMap));
    let mut slash = good_spec();
    slash.maps = vec![
        (PIN_PATH_RING.to_string(), MAP_TYPE_RINGBUF, 0),
        (DROPS_NAME.to_string(), MAP_TYPE_PERCPU_ARRAY, 0),
    ];
    assert_eq!(verdict(&slash)?, Err(ShapeError::ExtraMap));
    Ok(())
}


#[test]
fn a_missing_or_mistyped_map_is_named() -> Result<(), Box<dyn Error>> {
    let mut no_ring = good_spec();
    no_ring.maps = vec![(DROPS_NAME.to_string(), MAP_TYPE_PERCPU_ARRAY, 0)];
    assert_eq!(verdict(&no_ring)?, Err(ShapeError::MissingMap(RING_NAME)));
    let mut no_drops = good_spec();
    no_drops.maps = vec![(RING_NAME.to_string(), MAP_TYPE_RINGBUF, 0)];
    assert_eq!(verdict(&no_drops)?, Err(ShapeError::MissingMap(DROPS_NAME)));
    let mut ring_hash = good_spec();
    ring_hash.maps = vec![
        (RING_NAME.to_string(), MAP_TYPE_HASH, 0),
        (DROPS_NAME.to_string(), MAP_TYPE_PERCPU_ARRAY, 0),
    ];
    assert_eq!(verdict(&ring_hash)?, Err(ShapeError::WrongMapType(RING_NAME)));
    let mut drops_hash = good_spec();
    drops_hash.maps = vec![(RING_NAME.to_string(), MAP_TYPE_RINGBUF, 0), (DROPS_NAME.to_string(), MAP_TYPE_HASH, 0)];
    assert_eq!(verdict(&drops_hash)?, Err(ShapeError::WrongMapType(DROPS_NAME)));
    let mut no_rodata = good_spec();
    no_rodata.rodata = false;
    assert_eq!(verdict(&no_rodata)?, Err(ShapeError::MissingMap(RODATA_NAME)));
    let mut fake_rodata = good_spec();
    fake_rodata.rodata = false;
    fake_rodata.maps.push((RODATA_NAME.to_string(), MAP_TYPE_HASH, 0));
    assert_eq!(verdict(&fake_rodata)?, Err(ShapeError::WrongMapType(RODATA_NAME)));
    Ok(())
}


#[test]
fn a_missing_extra_or_mistyped_program_is_named() -> Result<(), Box<dyn Error>> {
    let mut none = good_spec();
    none.programs = Vec::new();
    assert_eq!(verdict(&none)?, Err(ShapeError::MissingProgram));
    let mut extra = good_spec();
    extra
        .programs
        .push(("tracepoint/sched/sched_process_fork".to_string(), "sched_process_fork".to_string()));
    assert_eq!(verdict(&extra)?, Err(ShapeError::ExtraProgram));
    let mut renamed = good_spec();
    renamed.programs = vec![(TRACEPOINT_SECTION.to_string(), "other_name".to_string())];
    assert_eq!(verdict(&renamed)?, Err(ShapeError::ExtraProgram));
    let mut kprobe = good_spec();
    kprobe.programs = vec![("kprobe/sched_process_exec".to_string(), PROGRAM_NAME.to_string())];
    assert_eq!(verdict(&kprobe)?, Err(ShapeError::WrongProgramType));
    Ok(())
}


#[test]
fn bytes_that_are_not_an_object_are_a_parse_refusal() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_object_bytes(b"not an elf"), Err(ShapeError::Parse));
    assert_eq!(check_object_bytes(&[]), Err(ShapeError::Parse));
    let whole = elf_of(&good_spec())?;
    let cut = whole.get(..LAST_SHORT_LENGTH).ok_or("short")?;
    assert_eq!(check_object_bytes(cut), Err(ShapeError::Parse));
    Ok(())
}


#[test]
fn every_refusal_has_fixed_text_without_object_content() -> Result<(), Box<dyn Error>> {
    let all = [
        ShapeError::Parse,
        ShapeError::PinnedMap,
        ShapeError::ExtraMap,
        ShapeError::MissingMap(RING_NAME),
        ShapeError::WrongMapType(DROPS_NAME),
        ShapeError::ExtraProgram,
        ShapeError::MissingProgram,
        ShapeError::WrongProgramType,
    ];
    let texts: Vec<String> = all.iter().map(ToString::to_string).collect();
    assert!(texts.iter().all(|text| text.starts_with("exec ") && !text.contains(MARKER)));
    assert_eq!(texts.iter().collect::<std::collections::HashSet<_>>().len(), all.len());
    assert!(all.iter().all(|error| std::error::Error::source(error).is_none()));
    let mut marked = good_spec();
    marked.maps.push((MARKER.to_string(), MAP_TYPE_HASH, 0));
    let refused = verdict(&marked)?.err().ok_or("accepted")?;
    assert!(!format!("{refused} {refused:?}").contains(MARKER));
    Ok(())
}
