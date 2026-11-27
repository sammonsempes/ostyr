#[cfg(unix)]
use crate::isolate::ChildRequest;
use mail_parser::{Header, Message};
#[cfg(unix)]
use std::io::{self, Read};


#[cfg(unix)]
pub type ReadFn = fn(&mut dyn Read, usize) -> io::Result<(Vec<u8>, bool)>;


#[cfg(unix)]
pub type Job = Box<dyn FnOnce() + Send + 'static>;


#[cfg(unix)]
pub type SpawnFn = fn(Job) -> io::Result<()>;


#[cfg(unix)]
pub type GroupKillFn = fn(rustix::process::Pid);


#[cfg(unix)]
pub type SerializeFn = fn(&ChildRequest) -> serde_json::Result<Vec<u8>>;


pub type RawReadFn = for<'a> fn(&'a Message<'_>, &Header<'_>) -> Option<&'a [u8]>;
