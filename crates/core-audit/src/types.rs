use std::collections::BTreeMap;
use std::sync::Arc;


pub type ParameterMap = BTreeMap<String, String>;


pub type Slot = Arc<crate::log::SlotCell>;


#[cfg(unix)]
pub type FactsReader = fn(&std::fs::File) -> std::io::Result<crate::log::HandleFacts>;


#[cfg(unix)]
pub type Reopener = fn(&std::path::Path, rustix::fs::OFlags) -> Result<std::fs::File, crate::error::AuditError>;
