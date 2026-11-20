use crate::isolate::ChildRequest;
use std::io::{self, Read};


pub type ReadFn = fn(&mut dyn Read, usize) -> io::Result<(Vec<u8>, bool)>;


pub type Job = Box<dyn FnOnce() + Send + 'static>;


pub type SpawnFn = fn(Job) -> io::Result<()>;


pub type SerializeFn = fn(&ChildRequest) -> serde_json::Result<Vec<u8>>;
