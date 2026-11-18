use std::collections::BTreeMap;


pub type ParameterMap = BTreeMap<String, String>;


#[cfg(unix)]
pub type FactsReader = fn(&std::fs::File) -> std::io::Result<crate::log::HandleFacts>;


#[cfg(unix)]
pub type Reopener = fn(&std::path::Path, rustix::fs::OFlags) -> Result<std::fs::File, crate::error::AuditError>;
