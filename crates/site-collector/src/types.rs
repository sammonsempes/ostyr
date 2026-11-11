use crate::error::SpoolError;
use crate::model::SourceState;
use crate::spool_model::{Segment, Spool};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr};


pub type Millis = u64;


pub type SourceId = IpAddr;


pub type SourceMap = BTreeMap<SourceId, SourceState>;


pub type SegmentList = VecDeque<Segment>;


pub type FrameWriter = fn(&mut File, &[u8]) -> io::Result<()>;


#[cfg(unix)]
pub type DirHandle = std::os::fd::OwnedFd;


#[cfg(not(unix))]
pub type DirHandle = std::path::PathBuf;


pub type RecvFn<'a> = dyn FnMut(&mut [u8]) -> io::Result<(usize, SocketAddr)> + 'a;


pub type NowFn<'a> = dyn Fn() -> Millis + 'a;


pub type YearFn<'a> = dyn Fn() -> i32 + 'a;


pub type CursorWriter = fn(&DirHandle, u64) -> io::Result<()>;


pub type SyncFn = fn(&Spool, u64, u64) -> Result<(), SpoolError>;


pub type DirSyncFn = fn(&DirHandle) -> io::Result<()>;
