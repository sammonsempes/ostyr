use crate::types::SkipCounts;
use core_pg::scope::TenantScope;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};


pub const DEFAULT_MAX_BYTES: u64 = 67_108_864;


pub const DEFAULT_MAX_SNAPSHOTS: usize = 100_000;


pub const DEFAULT_MAX_PATHS: usize = 256;


pub const DEFAULT_MAX_TAGS: usize = 64;


pub const DEFAULT_MAX_TEXT_CHARS: usize = 253;


pub const DEFAULT_MAX_PATH_BYTES: usize = 4096;


pub const DEFAULT_MAX_NAME_CHARS: usize = 255;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_snapshots: usize,
    pub max_paths: usize,
    pub max_tags: usize,
    pub max_text_chars: usize,
    pub max_path_bytes: usize,
    pub max_name_chars: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_snapshots: DEFAULT_MAX_SNAPSHOTS,
            max_paths: DEFAULT_MAX_PATHS,
            max_tags: DEFAULT_MAX_TAGS,
            max_text_chars: DEFAULT_MAX_TEXT_CHARS,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
            max_name_chars: DEFAULT_MAX_NAME_CHARS,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    BadId,
    BadTime,
    BadHost,
    BadName,
    BadPaths,
    BadTags,
    Duplicate,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub time: OffsetDateTime,
    pub host: Option<String>,
    pub paths: Vec<String>,
    pub tags: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub repository: String,
    pub snapshots: Vec<Snapshot>,
    pub skipped: SkipCounts,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticalHost {
    pub host: String,
    pub max_age_hours: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryFloor {
    pub repository: String,
    pub expected_min_snapshots: usize,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationsFile {
    pub tenant: String,
    #[serde(default)]
    pub hostname_from_name: bool,
    #[serde(default)]
    pub critical: Vec<CriticalHost>,
    #[serde(default)]
    pub repositories: Vec<RepositoryFloor>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declarations {
    pub tenant: TenantScope,
    pub hostname_from_name: bool,
    pub critical: Vec<CriticalHost>,
    pub repositories: Vec<RepositoryFloor>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageStatus {
    Ok,
    Stale { age: Duration },
    Missing,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub tenant: TenantScope,
    pub host: String,
    pub newest: Option<OffsetDateTime>,
    pub status: CoverageStatus,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    Deleted {
        id: String,
        time: OffsetDateTime,
        host: Option<String>,
    },
    RetentionBelowFloor {
        count: usize,
        floor: usize,
    },
    RepositoryChanged {
        previous: String,
        current: String,
    },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub tenant: TenantScope,
    pub repository: String,
    pub kind: FindingKind,
}
