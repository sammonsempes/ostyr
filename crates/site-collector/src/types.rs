use crate::model::SourceState;
use crate::spool_model::Segment;
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io;
use std::net::IpAddr;


pub type Millis = u64;


pub type SourceId = IpAddr;


pub type SourceMap = BTreeMap<SourceId, SourceState>;


pub type SegmentList = VecDeque<Segment>;


pub type FrameWriter = fn(&mut File, &[u8]) -> io::Result<()>;


#[cfg(unix)]
pub type DirHandle = std::os::fd::OwnedFd;


#[cfg(not(unix))]
pub type DirHandle = std::path::PathBuf;
