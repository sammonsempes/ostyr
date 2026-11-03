use crate::config::LimitOverrides;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use time::OffsetDateTime;


pub type ClockFn = dyn Fn() -> OffsetDateTime + Send + Sync;


pub type SyncFn = fn(&Path) -> io::Result<()>;


pub type TenantMap = BTreeMap<String, LimitOverrides>;
