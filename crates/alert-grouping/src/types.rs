use crate::model::{GroupKey, Work};
use std::collections::BTreeMap;


pub type OpenGroups<'alerts> = BTreeMap<GroupKey, Work<'alerts>>;
