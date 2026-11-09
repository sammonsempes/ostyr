use crate::model::ParamValue;
use std::collections::BTreeMap;
use std::io;
use std::process::{Child, ExitStatus};
use std::time::Duration;


pub type Params = BTreeMap<String, ParamValue>;


#[cfg(unix)]
pub type PlaceFn = fn(std::os::fd::BorrowedFd<'_>, u32) -> io::Result<()>;


#[cfg(unix)]
pub type CheckFn = fn(std::os::fd::BorrowedFd<'_>) -> io::Result<bool>;


#[cfg(unix)]
pub type StatFn = fn(std::os::fd::BorrowedFd<'_>) -> Result<rustix::fs::Stat, rustix::io::Errno>;


#[cfg(unix)]
pub type KillFn = fn(std::os::fd::BorrowedFd<'_>) -> io::Result<()>;


#[cfg(unix)]
pub type LimitFn = fn(std::os::fd::BorrowedFd<'_>, &crate::model::Limits) -> io::Result<()>;


#[cfg(unix)]
pub type EventsFn = fn(std::os::fd::BorrowedFd<'_>) -> io::Result<Option<crate::model::LimitHit>>;


#[cfg(unix)]
pub type NameFn<'a> = &'a mut dyn FnMut() -> io::Result<String>;


pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;
