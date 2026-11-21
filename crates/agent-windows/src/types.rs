use crate::error::RunError;
use crate::model::{CursorState, RunEnd, RunRequest};
use core_export::ecs::EcsEvent;
use core_export::error::ExportError;


pub type Runner<'a> = &'a mut dyn FnMut(&RunRequest<'_>, &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError>;


pub type EncodeFn = fn(&EcsEvent) -> Result<String, ExportError>;


pub type Found<'a> = (&'a CursorState, u64, Option<&'a str>);
