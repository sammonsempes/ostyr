use crate::model::{Attribute, IdentityKey};
use std::collections::{BTreeMap, BTreeSet};


pub type KeyMap = BTreeMap<IdentityKey, String>;


pub type AttributeMap = BTreeMap<String, Attribute>;


pub type ObservedMap = BTreeMap<String, String>;


pub type TruthMap = BTreeMap<String, String>;


pub type RowMap = BTreeMap<String, String>;


pub type ColumnMap = BTreeMap<String, String>;


pub type KeyColumnMap = BTreeMap<IdentityKey, String>;


pub type IdSet = BTreeSet<String>;


pub type RawRow = (u64, Result<RowMap, String>);
