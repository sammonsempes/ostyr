use crate::model::ParamValue;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;


pub type Params = BTreeMap<String, ParamValue>;


pub type PlaceFn = fn(&Path, u32) -> io::Result<()>;


#[cfg(unix)]
pub type CheckFn = fn(std::os::fd::BorrowedFd<'_>) -> io::Result<bool>;


#[cfg(unix)]
pub type StatFn = fn(std::os::fd::BorrowedFd<'_>) -> Result<rustix::fs::Stat, rustix::io::Errno>;


pub type KillFn = fn(&Path) -> io::Result<()>;


pub type NameFn<'a> = &'a mut dyn FnMut() -> io::Result<String>;


pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;
