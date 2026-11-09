use crate::model::DropReason;
use std::collections::BTreeMap;


pub type LabelMap = BTreeMap<String, String>;


pub type ResourceLabels = Result<LabelMap, DropReason>;


pub type Labels = Vec<(String, String)>;


pub type SeriesKey = (String, Labels);


pub type Dropped = BTreeMap<DropReason, u64>;
