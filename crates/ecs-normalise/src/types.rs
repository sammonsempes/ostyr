use crate::convert::Outcome;
use crate::error::NormaliseError;
use core_export::ecs::EcsEvent;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};


pub type LineNumber = u64;


pub type Handler = fn(Value, EcsEvent) -> Result<Outcome, NormaliseError>;


pub type Fields = BTreeMap<String, String>;


pub type SeenIds = BTreeSet<u32>;


pub type Label = (String, String);
