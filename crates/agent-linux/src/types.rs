use crate::model::SourceSettings;
use arc_swap::ArcSwap;
use std::sync::Arc;


pub type SharedSource = Arc<ArcSwap<SourceSettings>>;
