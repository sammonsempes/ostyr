use crate::model::{Attribute, IdentityKey};
use std::collections::BTreeMap;


pub type KeyMap = BTreeMap<IdentityKey, String>;


pub type AttributeMap = BTreeMap<String, Attribute>;


pub type ObservedMap = BTreeMap<String, String>;


pub type TruthMap = BTreeMap<String, String>;
