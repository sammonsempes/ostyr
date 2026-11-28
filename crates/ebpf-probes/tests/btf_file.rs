use ebpf_probes::btf::{lookup_of, parse_structs, Unsupported, MAX_BTF_BYTES, REASON_MISSING, REASON_OVERSIZED, REASON_TRUNCATED};
use ebpf_probes::btf_file::{
    find_file_offsets, nested_offset, offset_globals, offset_of, read_file_offsets, read_file_offsets_from, FileOffsets, MemberSpec, DENTRY_D_HASH,
    DENTRY_D_PARENT, FILE_F_FLAGS, FILE_F_INODE, FILE_F_MODE, FILE_F_PATH, GLOBAL_COUNT, HLIST_BL_NODE_PPREV, HLIST_STRUCT, INODE_I_INO, INODE_I_SB,
    MNT_NAMESPACE_NS, NSPROXY_MNT_NS, NS_COMMON_INUM, NS_COMMON_STRUCT, PATH_DENTRY, PATH_STRUCT, REASON_UNLISTED_STRUCT, STRUCTS, SUPER_BLOCK_S_DEV,
    TASK_NSPROXY,
};
use ebpf_probes::types::Rule;
use std::error::Error;
use std::io::Read;
use std::path::PathBuf;


const KIND_INT: u32 = 1;


const KIND_PTR: u32 = 2;


const KIND_STRUCT: u32 = 4;


const KIND_TYPEDEF: u32 = 8;


const KIND_SHIFT: u32 = 24;


const FLAG_SHIFT: u32 = 31;


const FIRST_WORD: u32 = 0x0001_EB9F;


const HEADER_BYTES: u32 = 24;


const INT4: u32 = 1;


const PTR: u32 = 3;


const FMODE_TYPEDEF: u32 = 4;


const PATH_ID: u32 = 5;


const HLIST_ID: u32 = 6;


const NEW_MEMBER_TYPE_BASE: u32 = 100;


const INT_BITS_FOUR_BYTES: u32 = 32;


const INT_BITS_EIGHT_BYTES: u32 = 64;


const FOUR: u32 = 4;


const EIGHT: u32 = 8;


const LONG8: u32 = 2;


const BITS: u32 = 8;


const BITFIELD_SHIFT: u32 = 24;


const FILE_SIZE: u32 = 256;


const SMALL_SIZE: u32 = 16;


const INODE_SIZE: u32 = 128;


const SUPER_BLOCK_SIZE: u32 = 256;


const DENTRY_SIZE: u32 = 64;


const TASK_SIZE: u32 = 128;


const NSPROXY_SIZE: u32 = 64;


const MNT_NAMESPACE_SIZE: u32 = 64;


const NS_COMMON_SIZE: u32 = 32;


const NS_COMMON_ID: u32 = 14;


const HEADER_WORDS: usize = 3;


const FILE_INDEX: usize = 2;


const ONE_BIT: u32 = 1;


const SPARSE: u64 = 1 << 40;


const TASK_GLOBALS: usize = 2;


const EXPECTED: FileOffsets = FileOffsets {
    file_mode: 68,
    file_flags: 64,
    file_path: 16,
    file_inode: 32,
    path_dentry: 8,
    inode_sb: 40,
    inode_ino: 64,
    super_block_dev: 16,
    dentry_parent: 24,
    dentry_hash_pprev: 16,
    task_nsproxy: 40,
    nsproxy_mnt_ns: 24,
    mnt_ns_inum: 24,
};


struct Def {
    name: String,
    size: u32,
    flagged: bool,
    members: Vec<(String, u32, u32)>,
}


struct Strings {
    bytes: Vec<u8>,
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("read failed"))
    }
}


fn push_word(buffer: &mut Vec<u8>, word: u32) {
    buffer.extend_from_slice(&word.to_le_bytes());
}


fn intern(strings: &mut Strings, name: &str) -> u32 {
    let offset = strings.bytes.len() as u32;
    strings.bytes.extend_from_slice(name.as_bytes());
    strings.bytes.push(0);
    offset
}


fn push_type(types: &mut Vec<u8>, header: [u32; HEADER_WORDS], extra: &[u32]) {
    header.iter().chain(extra).for_each(|word| push_word(types, *word));
}


fn at(bytes: u32) -> u32 {
    bytes * BITS
}


fn member(name: &str, type_id: u32, bits: u32) -> (String, u32, u32) {
    (name.to_string(), type_id, bits)
}


fn definitions() -> Vec<Def> {
    vec![
        Def {
            name: "path".into(),
            size: SMALL_SIZE,
            flagged: false,
            members: vec![member("mnt", PTR, 0), member("dentry", PTR, at(EXPECTED.path_dentry))],
        },
        Def {
            name: "hlist_bl_node".into(),
            size: SMALL_SIZE,
            flagged: false,
            members: vec![member("next", PTR, 0), member("pprev", PTR, at(EXPECTED.path_dentry))],
        },
        Def {
            name: "file".into(),
            size: FILE_SIZE,
            flagged: false,
            members: vec![
                member("f_path", PATH_ID, at(EXPECTED.file_path)),
                member("f_inode", PTR, at(EXPECTED.file_inode)),
                member("f_flags", INT4, at(EXPECTED.file_flags)),
                member("f_mode", FMODE_TYPEDEF, at(EXPECTED.file_mode)),
            ],
        },
        Def {
            name: "inode".into(),
            size: INODE_SIZE,
            flagged: false,
            members: vec![member("i_sb", PTR, at(EXPECTED.inode_sb)), member("i_ino", LONG8, at(EXPECTED.inode_ino))],
        },
        Def {
            name: "super_block".into(),
            size: SUPER_BLOCK_SIZE,
            flagged: false,
            members: vec![member("s_dev", INT4, at(EXPECTED.super_block_dev))],
        },
        Def {
            name: "dentry".into(),
            size: DENTRY_SIZE,
            flagged: false,
            members: vec![
                member("d_hash", HLIST_ID, at(EXPECTED.dentry_parent - SMALL_SIZE)),
                member("d_parent", PTR, at(EXPECTED.dentry_parent)),
            ],
        },
        Def {
            name: "task_struct".into(),
            size: TASK_SIZE,
            flagged: false,
            members: vec![member("nsproxy", PTR, at(EXPECTED.task_nsproxy))],
        },
        Def {
            name: "nsproxy".into(),
            size: NSPROXY_SIZE,
            flagged: false,
            members: vec![member("mnt_ns", PTR, at(EXPECTED.nsproxy_mnt_ns))],
        },
        Def {
            name: "mnt_namespace".into(),
            size: MNT_NAMESPACE_SIZE,
            flagged: false,
            members: vec![member("ns", NS_COMMON_ID, at(EIGHT))],
        },
        Def {
            name: "ns_common".into(),
            size: NS_COMMON_SIZE,
            flagged: false,
            members: vec![member("inum", INT4, at(SMALL_SIZE))],
        },
    ]
}


fn build(definitions: &[Def]) -> Vec<u8> {
    let mut strings = Strings { bytes: vec![0] };
    let mut types = Vec::new();
    push_type(&mut types, [0, KIND_INT << KIND_SHIFT, FOUR], &[INT_BITS_FOUR_BYTES]);
    push_type(&mut types, [0, KIND_INT << KIND_SHIFT, EIGHT], &[INT_BITS_EIGHT_BYTES]);
    push_type(&mut types, [0, KIND_PTR << KIND_SHIFT, INT4], &[]);
    push_type(&mut types, [0, KIND_TYPEDEF << KIND_SHIFT, INT4], &[]);
    definitions.iter().for_each(|def| {
        let name_offset = intern(&mut strings, &def.name);
        let header = (u32::from(def.flagged) << FLAG_SHIFT) | (KIND_STRUCT << KIND_SHIFT) | def.members.len() as u32;
        let extra = def
            .members
            .iter()
            .flat_map(|(member_name, type_id, bits)| [intern(&mut strings, member_name), *type_id, *bits])
            .collect::<Vec<u32>>();
        push_type(&mut types, [name_offset, header, def.size], &extra);
    });
    let mut bytes = Vec::new();
    let type_len = types.len() as u32;
    [FIRST_WORD, HEADER_BYTES, 0, type_len, type_len, strings.bytes.len() as u32]
        .iter()
        .for_each(|word| push_word(&mut bytes, *word));
    bytes.extend_from_slice(&types);
    bytes.extend_from_slice(&strings.bytes);
    bytes
}


fn def_mut<'a>(definitions: &'a mut [Def], name: &str) -> Result<&'a mut Def, Box<dyn Error>> {
    Ok(definitions.iter_mut().find(|def| def.name == name).ok_or("no such struct")?)
}


fn edit(definitions: &mut [Def], structure: &str, member_name: &str, type_id: u32, bits: u32) -> Result<(), Box<dyn Error>> {
    let slot = def_mut(definitions, structure)?
        .members
        .iter_mut()
        .find(|(candidate, _, _)| candidate == member_name)
        .ok_or("no such member")?;
    *slot = member(member_name, type_id, bits);
    Ok(())
}


fn rename_member(definitions: &mut [Def], spec: &MemberSpec) -> Result<(), Box<dyn Error>> {
    let slot = def_mut(definitions, spec.structure)?
        .members
        .iter_mut()
        .find(|(candidate, _, _)| candidate == spec.member)
        .ok_or("no such member")?;
    slot.0 = format!("x_{}", spec.member);
    Ok(())
}


fn rename_struct(definitions: &mut [Def], name: &str) -> Result<(), Box<dyn Error>> {
    def_mut(definitions, name)?.name = format!("x_{name}");
    Ok(())
}


fn all_specs() -> Vec<MemberSpec> {
    vec![
        FILE_F_MODE,
        FILE_F_FLAGS,
        FILE_F_PATH,
        FILE_F_INODE,
        PATH_DENTRY,
        INODE_I_SB,
        INODE_I_INO,
        SUPER_BLOCK_S_DEV,
        DENTRY_D_PARENT,
        DENTRY_D_HASH,
        HLIST_BL_NODE_PPREV,
        TASK_NSPROXY,
        NSPROXY_MNT_NS,
        MNT_NAMESPACE_NS,
        NS_COMMON_INUM,
    ]
}


fn wrong_type(spec: &MemberSpec) -> u32 {
    match spec.rule {
        Rule::Pointer => INT4,
        Rule::Int(_) | Rule::Struct(_) => PTR,
    }
}


fn failure(result: Result<FileOffsets, Unsupported>) -> Result<&'static str, Box<dyn Error>> {
    Ok(result.err().ok_or("unexpected success")?.0)
}


fn spec_offset(definitions: &[Def], spec: &MemberSpec) -> Result<u32, Unsupported> {
    let bytes = build(definitions);
    let names = STRUCTS.iter().map(|entry| entry.name).collect::<Vec<&str>>();
    let parsed = parse_structs(&bytes, &names)?;
    let lookup = lookup_of(&parsed);
    match spec.structure {
        "path" => nested_offset(&lookup, &parsed.found, (&FILE_F_PATH, PATH_STRUCT), spec).map(|(_, inner)| inner),
        "hlist_bl_node" => nested_offset(&lookup, &parsed.found, (&DENTRY_D_HASH, HLIST_STRUCT), spec).map(|(_, inner)| inner),
        "ns_common" => nested_offset(&lookup, &parsed.found, (&MNT_NAMESPACE_NS, NS_COMMON_STRUCT), spec).map(|(_, inner)| inner),
        _ => offset_of(&lookup, &parsed.found, spec),
    }
}


fn is_listed(spec: &MemberSpec) -> bool {
    STRUCTS.iter().any(|entry| entry.name == spec.structure)
}


#[test]
fn every_offset_is_read_in_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(find_file_offsets(&build(&definitions())), Ok(EXPECTED));
    Ok(())
}


#[test]
fn a_typedef_to_an_int_is_a_four_byte_int() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "file", "f_flags", FMODE_TYPEDEF, at(EXPECTED.file_flags))?;
    assert_eq!(find_file_offsets(&build(&defs)), Ok(EXPECTED));
    Ok(())
}


#[test]
fn a_missing_member_names_the_struct_and_member() -> Result<(), Box<dyn Error>> {
    all_specs().iter().try_for_each(|spec| -> Result<(), Box<dyn Error>> {
        let mut defs = definitions();
        rename_member(&mut defs, spec)?;
        assert_eq!(spec_offset(&defs, spec), Err(Unsupported(spec.missing)));
        assert!(spec.missing.contains(spec.member) && spec.missing.contains(spec.structure));
        Ok(())
    })
}


#[test]
fn a_member_of_the_wrong_type_names_the_struct_and_member() -> Result<(), Box<dyn Error>> {
    all_specs().iter().try_for_each(|spec| -> Result<(), Box<dyn Error>> {
        let mut defs = definitions();
        edit(&mut defs, spec.structure, spec.member, wrong_type(spec), 0)?;
        assert_eq!(spec_offset(&defs, spec), Err(Unsupported(spec.bad)));
        assert!(spec.bad.contains(spec.member) && spec.bad.contains(spec.structure));
        Ok(())
    })
}


#[test]
fn the_end_to_end_read_reports_the_first_bad_member() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "file", "f_path", PTR, at(EXPECTED.file_path))?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, FILE_F_PATH.bad);
    Ok(())
}


#[test]
fn an_embedded_struct_member_never_accepts_a_pointer() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "dentry", "d_hash", PTR, at(EXPECTED.dentry_parent - SMALL_SIZE))?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, DENTRY_D_HASH.bad);
    Ok(())
}


#[test]
fn an_embedded_struct_of_another_name_is_refused() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "file", "f_path", HLIST_ID, at(EXPECTED.file_path))?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, FILE_F_PATH.bad);
    Ok(())
}


#[test]
fn a_pointer_member_never_accepts_an_embedded_struct() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "file", "f_inode", PATH_ID, at(EXPECTED.file_inode))?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, FILE_F_INODE.bad);
    Ok(())
}


#[test]
fn an_int_of_the_wrong_size_is_refused() -> Result<(), Box<dyn Error>> {
    let mut wide_flags = definitions();
    edit(&mut wide_flags, "file", "f_flags", LONG8, at(EXPECTED.file_flags))?;
    assert_eq!(failure(find_file_offsets(&build(&wide_flags)))?, FILE_F_FLAGS.bad);
    let mut narrow_ino = definitions();
    edit(&mut narrow_ino, "inode", "i_ino", INT4, at(EXPECTED.inode_ino))?;
    assert_eq!(failure(find_file_offsets(&build(&narrow_ino)))?, INODE_I_INO.bad);
    let mut wide_dev = definitions();
    edit(&mut wide_dev, "super_block", "s_dev", LONG8, at(EXPECTED.super_block_dev))?;
    assert_eq!(failure(find_file_offsets(&build(&wide_dev)))?, SUPER_BLOCK_S_DEV.bad);
    Ok(())
}


#[test]
fn an_unaligned_member_and_a_bitfield_are_refused() -> Result<(), Box<dyn Error>> {
    let mut unaligned = definitions();
    edit(&mut unaligned, "file", "f_flags", INT4, at(EXPECTED.file_flags) + ONE_BIT)?;
    assert_eq!(failure(find_file_offsets(&build(&unaligned)))?, FILE_F_FLAGS.bad);
    let mut bitfield = definitions();
    def_mut(&mut bitfield, "file")?.flagged = true;
    edit(
        &mut bitfield,
        "file",
        "f_flags",
        INT4,
        (ONE_BIT << BITFIELD_SHIFT) | at(EXPECTED.file_flags),
    )?;
    assert_eq!(failure(find_file_offsets(&build(&bitfield)))?, FILE_F_FLAGS.bad);
    Ok(())
}


#[test]
fn a_flagged_struct_with_plain_members_is_read() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    def_mut(&mut defs, "file")?.flagged = true;
    assert_eq!(find_file_offsets(&build(&defs)), Ok(EXPECTED));
    Ok(())
}


#[test]
fn a_member_that_leaves_the_struct_is_refused_and_one_that_ends_at_the_size_is_accepted() -> Result<(), Box<dyn Error>> {
    let mut beyond = definitions();
    edit(&mut beyond, "file", "f_inode", PTR, at(FILE_SIZE - FOUR))?;
    assert_eq!(failure(find_file_offsets(&build(&beyond)))?, FILE_F_INODE.bad);
    let mut embedded_beyond = definitions();
    edit(&mut embedded_beyond, "file", "f_path", PATH_ID, at(FILE_SIZE - EIGHT))?;
    assert_eq!(failure(find_file_offsets(&build(&embedded_beyond)))?, FILE_F_PATH.bad);
    let mut exact = definitions();
    edit(&mut exact, "file", "f_path", PATH_ID, at(FILE_SIZE - SMALL_SIZE))?;
    assert_eq!(spec_offset(&exact, &FILE_F_PATH), Ok(FILE_SIZE - SMALL_SIZE));
    Ok(())
}


#[test]
fn an_unknown_type_id_is_a_bad_member() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    edit(&mut defs, "file", "f_inode", NEW_MEMBER_TYPE_BASE, at(EXPECTED.file_inode))?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, FILE_F_INODE.bad);
    Ok(())
}


#[test]
fn a_missing_struct_is_named_for_each_member_that_needs_it() -> Result<(), Box<dyn Error>> {
    all_specs()
        .iter()
        .filter(|spec| is_listed(spec))
        .try_for_each(|spec| -> Result<(), Box<dyn Error>> {
            let mut defs = definitions();
            rename_struct(&mut defs, spec.structure)?;
            let reason = STRUCTS.iter().find(|entry| entry.name == spec.structure).ok_or("unlisted")?.missing;
            assert_eq!(spec_offset(&defs, spec), Err(Unsupported(reason)));
            assert!(reason.contains(spec.structure));
            Ok(())
        })
}


#[test]
fn a_missing_file_struct_is_named_end_to_end() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    rename_struct(&mut defs, "file")?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, STRUCTS.first().ok_or("empty")?.missing);
    Ok(())
}


#[test]
fn a_spec_for_an_unlisted_struct_is_named() -> Result<(), Box<dyn Error>> {
    let stray = MemberSpec {
        structure: "nowhere",
        ..FILE_F_MODE
    };
    assert_eq!(spec_offset(&definitions(), &stray), Err(Unsupported(REASON_UNLISTED_STRUCT)));
    Ok(())
}


#[test]
fn a_struct_defined_twice_is_refused_by_name_for_each_wanted_struct() -> Result<(), Box<dyn Error>> {
    STRUCTS.iter().try_for_each(|entry| -> Result<(), Box<dyn Error>> {
        let mut defs = definitions();
        let copy = definitions().into_iter().find(|def| def.name == entry.name).ok_or("no such struct")?;
        defs.push(copy);
        assert_eq!(failure(find_file_offsets(&build(&defs)))?, entry.duplicate);
        assert!(entry.duplicate.contains(entry.name));
        Ok(())
    })
}


#[test]
fn a_struct_defined_three_times_is_still_refused() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    let first = definitions().into_iter().nth(FILE_INDEX).ok_or("no file")?;
    let second = definitions().into_iter().nth(FILE_INDEX).ok_or("no file")?;
    defs.push(first);
    defs.push(second);
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, STRUCTS.first().ok_or("empty")?.duplicate);
    Ok(())
}


#[test]
fn the_rodata_globals_carry_every_offset_under_the_names_the_kernel_program_declares() -> Result<(), Box<dyn Error>> {
    let globals = offset_globals(&EXPECTED);
    assert_eq!(globals.len(), GLOBAL_COUNT);
    let values: Vec<u64> = globals.iter().map(|(_, value)| *value).collect();
    let expected = [
        EXPECTED.file_mode,
        EXPECTED.file_flags,
        EXPECTED.file_path,
        EXPECTED.file_inode,
        EXPECTED.path_dentry,
        EXPECTED.inode_sb,
        EXPECTED.inode_ino,
        EXPECTED.super_block_dev,
        EXPECTED.dentry_parent,
        EXPECTED.dentry_hash_pprev,
        EXPECTED.task_nsproxy,
        EXPECTED.nsproxy_mnt_ns,
        EXPECTED.mnt_ns_inum,
    ]
    .map(u64::from);
    assert_eq!(values, expected);
    let kernel = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ebpf/src/main.rs"))?;
    globals.iter().for_each(|(name, _)| {
        assert!(
            kernel.contains(&format!("static {name}: u64 = 0;")),
            "{name} is not declared by the kernel program"
        )
    });
    let declared = kernel.matches(": u64 = 0;").count();
    assert_eq!(declared, GLOBAL_COUNT + TASK_GLOBALS);
    Ok(())
}


#[test]
fn a_cut_type_section_is_truncated() -> Result<(), Box<dyn Error>> {
    let mut bytes = build(&definitions());
    let cut = bytes.len() - 1;
    bytes.truncate(cut);
    assert_eq!(failure(find_file_offsets(&bytes))?, REASON_TRUNCATED);
    Ok(())
}


#[test]
fn a_reader_is_read_once_and_bounded() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_file_offsets_from(build(&definitions()).as_slice()), Ok(EXPECTED));
    assert_eq!(failure(read_file_offsets_from(FailingReader))?, "BTF file cannot be read");
    let oversized = std::io::repeat(0).take(MAX_BTF_BYTES + 1);
    assert_eq!(failure(read_file_offsets_from(oversized))?, REASON_OVERSIZED);
    Ok(())
}


#[test]
fn the_production_open_reads_a_file_and_names_a_missing_one() -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("btf_file_sample.bin");
    std::fs::write(&path, build(&definitions()))?;
    assert_eq!(read_file_offsets(&path), Ok(EXPECTED));
    assert_eq!(failure(read_file_offsets(&path.with_extension("missing")))?, REASON_MISSING);
    Ok(())
}


#[test]
fn a_sparse_file_over_a_terabyte_is_refused_by_the_production_open() -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("btf_file_sparse.bin");
    std::fs::File::create(&path)?.set_len(SPARSE)?;
    assert_eq!(failure(read_file_offsets(&path))?, REASON_OVERSIZED);
    Ok(())
}


#[test]
fn a_nested_struct_that_is_not_present_refuses_the_outer_member() -> Result<(), Box<dyn Error>> {
    let mut no_path = definitions();
    rename_struct(&mut no_path, "path")?;
    assert_eq!(failure(find_file_offsets(&build(&no_path)))?, FILE_F_PATH.bad);
    let mut no_hlist = definitions();
    rename_struct(&mut no_hlist, "hlist_bl_node")?;
    assert_eq!(failure(find_file_offsets(&build(&no_hlist)))?, DENTRY_D_HASH.bad);
    Ok(())
}


const DECOY_SIZE: u32 = 4000;


const DECOY_PPREV: u32 = 3008;


const REAL_PATH_ID: u32 = 15;


const REAL_HLIST_ID: u32 = 16;


fn decoy_first(definitions: &mut [Def]) -> Result<(), Box<dyn Error>> {
    let hlist = def_mut(definitions, "hlist_bl_node")?;
    hlist.size = DECOY_SIZE;
    hlist.members = vec![member("next", PTR, 0), member("pprev", PTR, at(DECOY_PPREV))];
    let path = def_mut(definitions, "path")?;
    path.members = vec![member("mnt", PTR, 0), member("dentry", PTR, at(FOUR))];
    Ok(())
}


fn with_real_copies(target: &mut Vec<Def>) -> Result<(), Box<dyn Error>> {
    let real = definitions();
    target.push(Def {
        name: "path".into(),
        ..real.into_iter().next().ok_or("no path")?
    });
    target.push(Def {
        name: "hlist_bl_node".into(),
        size: SMALL_SIZE,
        flagged: false,
        members: vec![member("next", PTR, 0), member("pprev", PTR, at(EXPECTED.path_dentry))],
    });
    edit(target, "file", "f_path", REAL_PATH_ID, at(EXPECTED.file_path))?;
    edit(target, "dentry", "d_hash", REAL_HLIST_ID, at(EXPECTED.dentry_parent - SMALL_SIZE))?;
    Ok(())
}


#[test]
fn a_duplicated_nested_struct_is_resolved_by_the_type_the_member_uses() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    decoy_first(&mut defs)?;
    with_real_copies(&mut defs)?;
    assert_eq!(find_file_offsets(&build(&defs)), Ok(EXPECTED));
    Ok(())
}


#[test]
fn a_nested_struct_larger_than_its_dentry_fails_the_outer_fit_check() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    decoy_first(&mut defs)?;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, DENTRY_D_HASH.bad);
    Ok(())
}


#[test]
fn a_used_nested_struct_larger_than_its_outer_is_refused() -> Result<(), Box<dyn Error>> {
    let mut defs = definitions();
    def_mut(&mut defs, "hlist_bl_node")?.size = DENTRY_SIZE;
    assert_eq!(failure(find_file_offsets(&build(&defs)))?, DENTRY_D_HASH.bad);
    Ok(())
}
