//! Type aliases of the host crate.

use crate::btf::{TaskStruct, MEMBER_WORDS};
#[cfg(target_os = "linux")]
use crate::object::Meta;
use crate::record::DecodeError;
#[cfg(target_os = "linux")]
use rustix::fs::OFlags;
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::os::fd::{BorrowedFd, OwnedFd};


pub type DecodeFn<Item> = fn(&[u8]) -> Result<Item, DecodeError>;


pub type TimeFn<Item> = fn(&Item) -> u64;


pub type Walked = (usize, Option<TaskStruct>);


pub type Member = [u32; MEMBER_WORDS];


pub type Resolved = (u32, usize);


#[derive(Clone, Copy, Debug)]
pub struct Lookup<'a> {
    pub types: &'a [u8],
    pub strings: &'a [u8],
    pub index: &'a [usize],
}


pub type ExtraType<'a> = (u32, u32, &'a [u32]);


#[cfg(target_os = "linux")]
pub type Opened = (OwnedFd, Meta);


#[cfg(target_os = "linux")]
pub type OpenFn = fn(BorrowedFd<'_>, &OsStr, OFlags) -> Result<Opened, Errno>;


#[cfg(target_os = "linux")]
pub type StatFn = fn(BorrowedFd<'_>, &OsStr) -> Result<Meta, Errno>;
