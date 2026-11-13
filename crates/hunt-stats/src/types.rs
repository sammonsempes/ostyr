use crate::model::KeyReport;
use std::collections::{BTreeMap, BTreeSet};


pub type Entity = String;


pub type Key = String;


pub type RareReport = KeyReport;


pub type Observation = (Entity, Key);


pub type Grouped = (BTreeMap<String, BTreeSet<String>>, usize);
