use crate::plan::Change;
use crate::secret::SecretRef;
use core_audit::error::AuditError;
use core_audit::model::{NewEntry, Record};
use std::collections::BTreeMap;
use std::error::Error;


pub type SecretMap = BTreeMap<String, SecretRef>;


pub type SettingsMap = BTreeMap<String, String>;


pub type ConfigState = BTreeMap<String, String>;


pub type Plan = Vec<Change>;


pub type BoxError = Box<dyn Error + Send + Sync>;


pub type ApplierFn<'a> = dyn FnMut(&Change) -> Result<(), BoxError> + 'a;


pub type ReaderFn<'a> = dyn FnMut() -> Result<ConfigState, BoxError> + 'a;


pub type AuditFn<'a> = dyn FnMut(NewEntry) -> Result<Record, AuditError> + 'a;
