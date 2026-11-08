use std::collections::BTreeMap;


pub type Row = BTreeMap<String, String>;


pub type QueryResult<'a> = Result<&'a [Row], &'a str>;
