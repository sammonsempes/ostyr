use crate::model::ParamValue;
use std::collections::BTreeMap;
use std::io;
use std::process::{Child, ExitStatus};
use std::time::Duration;


pub type Params = BTreeMap<String, ParamValue>;


pub type WaitFn = fn(&mut Child, Duration) -> io::Result<Option<ExitStatus>>;
