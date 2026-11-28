//! Byte offsets of the `struct file`, `inode`, `super_block` and `dentry` members the file-open probe reads, from the kernel BTF.

use crate::btf::{
    lookup_of, member_offset, member_struct, members_of, open_btf, parse_structs, read_btf_bytes, TaskStruct, Unsupported, REASON_BITFIELD,
    REASON_MEMBER_TYPE, REASON_OUT_OF_STRUCT, REASON_TYPE_CHAIN,
};
use crate::types::{Lookup, Rule};
use std::io::Read;
use std::path::Path;


pub const INT_BYTES: u32 = 4;


pub const LONG_BYTES: u32 = 8;


pub const PATH_STRUCT: &str = "path";


pub const HLIST_STRUCT: &str = "hlist_bl_node";


pub const REASON_UNLISTED_STRUCT: &str = "the member list names a struct the reader does not look for";


/// A struct whose body must be found, and the fixed reason when it is not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructSpec {
    pub name: &'static str,
    pub missing: &'static str,
    pub duplicate: &'static str,
}


/// A member of a struct, its required type and the fixed reasons naming both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberSpec {
    pub structure: &'static str,
    pub member: &'static str,
    pub rule: Rule,
    pub missing: &'static str,
    pub bad: &'static str,
}


/// Offsets in bytes; `dentry_hash_pprev` is `dentry.d_hash` plus `hlist_bl_node.pprev`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOffsets {
    pub file_mode: u32,
    pub file_flags: u32,
    pub file_path: u32,
    pub file_inode: u32,
    pub path_dentry: u32,
    pub inode_sb: u32,
    pub inode_ino: u32,
    pub super_block_dev: u32,
    pub dentry_parent: u32,
    pub dentry_hash_pprev: u32,
    pub task_nsproxy: u32,
    pub nsproxy_mnt_ns: u32,
    pub mnt_ns_inum: u32,
}


pub const STRUCTS: &[StructSpec] = &[
    StructSpec {
        name: "file",
        missing: "BTF has no struct file",
        duplicate: "duplicate struct file",
    },
    StructSpec {
        name: "inode",
        missing: "BTF has no struct inode",
        duplicate: "duplicate struct inode",
    },
    StructSpec {
        name: "super_block",
        missing: "BTF has no struct super_block",
        duplicate: "duplicate struct super_block",
    },
    StructSpec {
        name: "dentry",
        missing: "BTF has no struct dentry",
        duplicate: "duplicate struct dentry",
    },
    StructSpec {
        name: "task_struct",
        missing: "BTF has no struct task_struct",
        duplicate: "duplicate struct task_struct",
    },
    StructSpec {
        name: "nsproxy",
        missing: "BTF has no struct nsproxy",
        duplicate: "duplicate struct nsproxy",
    },
    StructSpec {
        name: "mnt_namespace",
        missing: "BTF has no struct mnt_namespace",
        duplicate: "duplicate struct mnt_namespace",
    },
];


pub const FILE_F_MODE: MemberSpec = MemberSpec {
    structure: "file",
    member: "f_mode",
    rule: Rule::Int(INT_BYTES),
    missing: "struct file has no f_mode member",
    bad: "struct file f_mode is not a 4-byte aligned integer inside the struct",
};


pub const FILE_F_FLAGS: MemberSpec = MemberSpec {
    structure: "file",
    member: "f_flags",
    rule: Rule::Int(INT_BYTES),
    missing: "struct file has no f_flags member",
    bad: "struct file f_flags is not a 4-byte aligned integer inside the struct",
};


pub const FILE_F_PATH: MemberSpec = MemberSpec {
    structure: "file",
    member: "f_path",
    rule: Rule::Struct(PATH_STRUCT),
    missing: "struct file has no f_path member",
    bad: "struct file f_path is not an embedded struct path inside the struct",
};


pub const FILE_F_INODE: MemberSpec = MemberSpec {
    structure: "file",
    member: "f_inode",
    rule: Rule::Pointer,
    missing: "struct file has no f_inode member",
    bad: "struct file f_inode is not an aligned pointer inside the struct",
};


pub const PATH_DENTRY: MemberSpec = MemberSpec {
    structure: "path",
    member: "dentry",
    rule: Rule::Pointer,
    missing: "struct path has no dentry member",
    bad: "struct path dentry is not an aligned pointer inside the struct",
};


pub const INODE_I_SB: MemberSpec = MemberSpec {
    structure: "inode",
    member: "i_sb",
    rule: Rule::Pointer,
    missing: "struct inode has no i_sb member",
    bad: "struct inode i_sb is not an aligned pointer inside the struct",
};


pub const INODE_I_INO: MemberSpec = MemberSpec {
    structure: "inode",
    member: "i_ino",
    rule: Rule::Int(LONG_BYTES),
    missing: "struct inode has no i_ino member",
    bad: "struct inode i_ino is not an 8-byte aligned integer inside the struct",
};


pub const SUPER_BLOCK_S_DEV: MemberSpec = MemberSpec {
    structure: "super_block",
    member: "s_dev",
    rule: Rule::Int(INT_BYTES),
    missing: "struct super_block has no s_dev member",
    bad: "struct super_block s_dev is not a 4-byte aligned integer inside the struct",
};


pub const DENTRY_D_PARENT: MemberSpec = MemberSpec {
    structure: "dentry",
    member: "d_parent",
    rule: Rule::Pointer,
    missing: "struct dentry has no d_parent member",
    bad: "struct dentry d_parent is not an aligned pointer inside the struct",
};


pub const DENTRY_D_HASH: MemberSpec = MemberSpec {
    structure: "dentry",
    member: "d_hash",
    rule: Rule::Struct(HLIST_STRUCT),
    missing: "struct dentry has no d_hash member",
    bad: "struct dentry d_hash is not an embedded struct hlist_bl_node inside the struct",
};


pub const HLIST_BL_NODE_PPREV: MemberSpec = MemberSpec {
    structure: "hlist_bl_node",
    member: "pprev",
    rule: Rule::Pointer,
    missing: "struct hlist_bl_node has no pprev member",
    bad: "struct hlist_bl_node pprev is not an aligned pointer inside the struct",
};


pub const GLOBAL_COUNT: usize = 13;


pub const NS_COMMON_STRUCT: &str = "ns_common";


pub const TASK_NSPROXY: MemberSpec = MemberSpec {
    structure: "task_struct",
    member: "nsproxy",
    rule: Rule::Pointer,
    missing: "struct task_struct has no nsproxy member",
    bad: "struct task_struct nsproxy is not an aligned pointer inside the struct",
};


pub const NSPROXY_MNT_NS: MemberSpec = MemberSpec {
    structure: "nsproxy",
    member: "mnt_ns",
    rule: Rule::Pointer,
    missing: "struct nsproxy has no mnt_ns member",
    bad: "struct nsproxy mnt_ns is not an aligned pointer inside the struct",
};


pub const MNT_NAMESPACE_NS: MemberSpec = MemberSpec {
    structure: "mnt_namespace",
    member: "ns",
    rule: Rule::Struct(NS_COMMON_STRUCT),
    missing: "struct mnt_namespace has no ns member",
    bad: "struct mnt_namespace ns is not an embedded struct ns_common inside the struct",
};


pub const NS_COMMON_INUM: MemberSpec = MemberSpec {
    structure: "ns_common",
    member: "inum",
    rule: Rule::Int(INT_BYTES),
    missing: "struct ns_common has no inum member",
    bad: "struct ns_common inum is not a 4-byte aligned integer inside the struct",
};


/// The rodata globals the kernel program reads, as name and value; the names are the `static` items of `ebpf/src/main.rs`.
pub fn offset_globals(offsets: &FileOffsets) -> [(&'static str, u64); GLOBAL_COUNT] {
    [
        ("FILE_MODE_OFFSET", u64::from(offsets.file_mode)),
        ("FILE_FLAGS_OFFSET", u64::from(offsets.file_flags)),
        ("FILE_PATH_OFFSET", u64::from(offsets.file_path)),
        ("FILE_INODE_OFFSET", u64::from(offsets.file_inode)),
        ("PATH_DENTRY_OFFSET", u64::from(offsets.path_dentry)),
        ("INODE_SB_OFFSET", u64::from(offsets.inode_sb)),
        ("INODE_INO_OFFSET", u64::from(offsets.inode_ino)),
        ("SUPER_BLOCK_DEV_OFFSET", u64::from(offsets.super_block_dev)),
        ("DENTRY_PARENT_OFFSET", u64::from(offsets.dentry_parent)),
        ("DENTRY_HASH_PPREV_OFFSET", u64::from(offsets.dentry_hash_pprev)),
        ("TASK_NSPROXY_OFFSET", u64::from(offsets.task_nsproxy)),
        ("NSPROXY_MNT_NS_OFFSET", u64::from(offsets.nsproxy_mnt_ns)),
        ("MNT_NS_INUM_OFFSET", u64::from(offsets.mnt_ns_inum)),
    ]
}


/// Opens the BTF file once and reads the file-probe offsets from that handle.
pub fn read_file_offsets(path: &Path) -> Result<FileOffsets, Unsupported> {
    let file = open_btf(path)?;
    read_file_offsets_from(file)
}


/// Reads at most `MAX_BTF_BYTES` from the reader, refusing anything longer.
pub fn read_file_offsets_from<Source: Read>(reader: Source) -> Result<FileOffsets, Unsupported> {
    let data = read_btf_bytes(reader)?;
    find_file_offsets(&data)
}


/// Walks the type section of raw BTF bytes once and resolves every member by its own rule; a nested struct is the type the outer member uses.
pub fn find_file_offsets(data: &[u8]) -> Result<FileOffsets, Unsupported> {
    let names = STRUCTS.iter().map(|spec| spec.name).collect::<Vec<&str>>();
    let parsed = parse_structs(data, &names)?;
    let lookup = lookup_of(&parsed);
    let found = &parsed.found;
    let repeated = STRUCTS
        .iter()
        .zip(&parsed.duplicated)
        .find(|(_, again)| **again)
        .map(|(spec, _)| Unsupported(spec.duplicate));
    repeated.map_or(Ok(()), Err)?;
    let (file_path, path_dentry) = nested_offset(&lookup, found, (&FILE_F_PATH, PATH_STRUCT), &PATH_DENTRY)?;
    let (hash, pprev) = nested_offset(&lookup, found, (&DENTRY_D_HASH, HLIST_STRUCT), &HLIST_BL_NODE_PPREV)?;
    let dentry_hash_pprev = hash.checked_add(pprev).ok_or(Unsupported(DENTRY_D_HASH.bad))?;
    let (namespace, inum) = nested_offset(&lookup, found, (&MNT_NAMESPACE_NS, NS_COMMON_STRUCT), &NS_COMMON_INUM)?;
    let mnt_ns_inum = namespace.checked_add(inum).ok_or(Unsupported(MNT_NAMESPACE_NS.bad))?;
    Ok(FileOffsets {
        file_mode: offset_of(&lookup, found, &FILE_F_MODE)?,
        file_flags: offset_of(&lookup, found, &FILE_F_FLAGS)?,
        file_path,
        file_inode: offset_of(&lookup, found, &FILE_F_INODE)?,
        path_dentry,
        inode_sb: offset_of(&lookup, found, &INODE_I_SB)?,
        inode_ino: offset_of(&lookup, found, &INODE_I_INO)?,
        super_block_dev: offset_of(&lookup, found, &SUPER_BLOCK_S_DEV)?,
        dentry_parent: offset_of(&lookup, found, &DENTRY_D_PARENT)?,
        dentry_hash_pprev,
        task_nsproxy: offset_of(&lookup, found, &TASK_NSPROXY)?,
        nsproxy_mnt_ns: offset_of(&lookup, found, &NSPROXY_MNT_NS)?,
        mnt_ns_inum,
    })
}


/// The offset of one member of a found struct; a refusal of its shape names the struct and member.
pub fn offset_of(lookup: &Lookup, found: &[Option<TaskStruct>], spec: &MemberSpec) -> Result<u32, Unsupported> {
    let body = body_of(found, spec.structure)?;
    let members = members_of(lookup.types, &body);
    member_offset(lookup, &members, &body, (spec.member, spec.missing), spec.rule).map_err(|error| shape_reason(error, spec))
}


/// The offsets of an embedded struct member `outer` and of `inner` inside the type `outer` resolves to.
pub fn nested_offset(
    lookup: &Lookup,
    found: &[Option<TaskStruct>],
    outer: (&MemberSpec, &'static str),
    inner: &MemberSpec,
) -> Result<(u32, u32), Unsupported> {
    let body = body_of(found, outer.0.structure)?;
    let members = members_of(lookup.types, &body);
    let (outer_offset, nested) =
        member_struct(lookup, &members, &body, (outer.0.member, outer.0.missing), outer.1).map_err(|error| shape_reason(error, outer.0))?;
    let nested_members = members_of(lookup.types, &nested);
    let inner_offset =
        member_offset(lookup, &nested_members, &nested, (inner.member, inner.missing), inner.rule).map_err(|error| shape_reason(error, inner))?;
    Ok((outer_offset, inner_offset))
}


fn body_of(found: &[Option<TaskStruct>], structure: &str) -> Result<TaskStruct, Unsupported> {
    STRUCTS
        .iter()
        .zip(found)
        .filter(|(candidate, _)| candidate.name == structure)
        .map(|(candidate, slot)| slot.ok_or(Unsupported(candidate.missing)))
        .next()
        .unwrap_or(Err(Unsupported(REASON_UNLISTED_STRUCT)))
}


fn shape_reason(error: Unsupported, spec: &MemberSpec) -> Unsupported {
    match error.0 {
        REASON_BITFIELD | REASON_MEMBER_TYPE | REASON_TYPE_CHAIN | REASON_OUT_OF_STRUCT => Unsupported(spec.bad),
        _ => error,
    }
}
