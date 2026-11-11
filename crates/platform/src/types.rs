use core_api::types::ModuleParts;
use core_pg::migrate::Migration;


pub type MigrationPlan = Vec<(&'static str, &'static [Migration])>;


pub type Parts = ModuleParts;
