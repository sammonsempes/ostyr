#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::fs::{File, Metadata};
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::OwnedFd;


#[cfg(unix)]
pub type ListerFn = fn(&OwnedFd, usize) -> Result<Vec<Vec<u8>>, Errno>;


#[cfg(unix)]
pub type InspectFn = fn(&File) -> io::Result<Metadata>;
