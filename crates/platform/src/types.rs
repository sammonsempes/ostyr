use crate::model::Module;
use core_api::types::ModuleParts;
use core_pg::migrate::Migration;
use status_page::error::StatusPageError;
use status_page::model::PageConfig;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub type MigrationPlan = Vec<(&'static str, &'static [Migration])>;


pub type Parts = ModuleParts;


/// One connection semaphore per selected module.
pub type Permits = Vec<(Module, Arc<Semaphore>)>;


/// Reads and validates the page file: injected so a test counts the reads, production passes `load_config` with the default limits.
pub type PageLoader<'a> = &'a dyn Fn(&Path) -> Result<PageConfig, StatusPageError>;
