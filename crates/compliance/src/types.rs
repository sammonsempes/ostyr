use std::collections::BTreeMap;


pub type Row = BTreeMap<String, String>;


pub type QueryResult<'a> = Result<&'a [Row], &'a str>;


pub type StateKey = (String, String, String);


pub type RunEntry<'a> = (&'a str, &'a str, &'a str, &'a crate::model::Verdict);


pub type PlannedEntry = (StateKey, &'static str);
