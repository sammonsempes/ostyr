use crate::model::ParamValue;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;


pub type Params = BTreeMap<String, ParamValue>;


pub type PlaceFn = fn(&Path, u32) -> io::Result<()>;


pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;
