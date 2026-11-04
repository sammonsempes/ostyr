use crate::selection::FieldTest;
use crate::window::Hit;
use std::collections::BTreeMap;


pub type RuleTexts = BTreeMap<String, String>;


pub type GroupMap = BTreeMap<String, Vec<Hit>>;


pub type Selection = Vec<Vec<FieldTest>>;


pub type SelectionResults = BTreeMap<String, bool>;
