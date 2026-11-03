use crate::convert::Outcome;
use crate::error::NormaliseError;
use core_export::ecs::EcsEvent;
use serde_json::Value;


pub type LineNumber = u64;


pub type Handler = fn(Value, EcsEvent) -> Result<Outcome, NormaliseError>;
