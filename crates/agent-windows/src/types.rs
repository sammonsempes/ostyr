use crate::error::RunError;
use crate::model::{CursorState, RunEnd, RunRequest};
use core_export::ecs::EcsEvent;
use core_export::error::ExportError;


pub type Runner<'a> = &'a mut dyn FnMut(&RunRequest<'_>, &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError>;


pub type Sink<'a> = &'a mut dyn FnMut(&str) -> std::io::Result<()>;


pub type EncodeFn = fn(&EcsEvent) -> Result<String, ExportError>;


pub type Found<'a> = (&'a CursorState, u64, Option<&'a str>);


pub type Raw = Box<serde_json::value::RawValue>;


/// What a settings file looked like when a reload refused it: its bytes, or the text of the read error.
pub type Fingerprint = Result<Vec<u8>, String>;


/// The loader's record shared with the round loop.
pub type SharedObserved = std::sync::Arc<std::sync::Mutex<crate::settings::Observed>>;
