use serde::Deserialize;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntPackFile {
    pub packs: Vec<HuntPack>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Clickhouse,
    Osquery,
}


/// `max_bytes_read` is required for ClickHouse packs and refused for osquery packs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub max_rows: u64,
    pub max_seconds: u64,
    pub max_bytes_read: Option<u64>,
}


/// `max_matches` is the match count above which a run yields a finding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub max_matches: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackTest {
    pub corpus: String,
    pub expect_matches: u64,
}


/// Durations are in seconds; `corpus` of a test is a relative path to a lab corpus file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HuntPack {
    pub id: String,
    pub title: String,
    pub hypothesis: String,
    pub technique: String,
    pub source: Source,
    pub query: String,
    pub schedule_seconds: u64,
    pub window_seconds: u64,
    pub cost: Cost,
    pub baseline: Baseline,
    #[serde(default)]
    pub tests: Vec<PackTest>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPack {
    pub file: String,
    pub pack: HuntPack,
}
