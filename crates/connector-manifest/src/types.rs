#[cfg(target_os = "linux")]
use rustix::fs::OFlags;
#[cfg(target_os = "linux")]
use rustix::io::Errno;
#[cfg(target_os = "linux")]
use std::fs::{File, Metadata};
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{BorrowedFd, OwnedFd};


#[cfg(target_os = "linux")]
pub type ListerFn = fn(&OwnedFd, usize) -> Result<Vec<Vec<u8>>, Errno>;


#[cfg(target_os = "linux")]
pub type InspectFn = fn(&File) -> io::Result<Metadata>;


#[cfg(target_os = "linux")]
pub type OpenFn = fn(BorrowedFd<'_>, &str, OFlags) -> Result<OwnedFd, Errno>;


pub type WriteFn = fn(&mut std::fs::File, &[u8]) -> std::io::Result<()>;
