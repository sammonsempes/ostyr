use crate::error::ConfigError;
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


pub type LoaderFn<Config> = dyn Fn() -> Result<Config, ConfigError> + Send + Sync;


pub type StateFn<Config> = fn(&Config) -> ConfigState;


pub type SharedAuditFn = dyn Fn(NewEntry) -> Result<Record, AuditError> + Send + Sync;


pub type ValidateFn<Config> = dyn Fn(&Config) -> Result<(), BoxError> + Send + Sync;


pub type ApplySectionFn<Config> = dyn Fn(&Config) + Send + Sync;
