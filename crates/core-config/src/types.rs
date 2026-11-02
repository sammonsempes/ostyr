use crate::secret::SecretRef;
use std::collections::BTreeMap;


pub type SecretMap = BTreeMap<String, SecretRef>;


pub type SettingsMap = BTreeMap<String, String>;
