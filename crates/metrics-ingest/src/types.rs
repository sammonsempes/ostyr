use crate::model::DropReason;
use std::collections::BTreeMap;
use std::time::Duration;


pub type LabelMap = BTreeMap<String, String>;


pub type ResourceLabels = Result<LabelMap, DropReason>;


pub type Labels = Vec<(String, String)>;


pub type SeriesKey = (String, Labels);


pub type Dropped = BTreeMap<DropReason, u64>;


pub type TenantMonth = (String, i32, u8);


pub type Groups = BTreeMap<TenantMonth, Vec<Vec<u8>>>;


pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;
