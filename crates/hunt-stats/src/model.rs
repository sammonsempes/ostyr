pub const DEFAULT_MAX_ROWS: usize = 1_000_000;


pub const DEFAULT_MAX_KEYS: usize = 100_000;


pub const DEFAULT_MAX_EXAMPLES: usize = 5;


pub const DEFAULT_MAX_TIMESTAMPS: usize = 100_000;


pub const DEFAULT_MIN_EVENTS: usize = 8;


pub const DEFAULT_MIN_MEDIAN_SECONDS: i64 = 1;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackLimits {
    pub max_rows: usize,
    pub max_keys: usize,
    pub max_examples: usize,
}


impl Default for StackLimits {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_MAX_ROWS,
            max_keys: DEFAULT_MAX_KEYS,
            max_examples: DEFAULT_MAX_EXAMPLES,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntities {
    pub key: String,
    pub entities: usize,
    pub examples: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    pub keys: Vec<KeyEntities>,
    pub rows_dropped: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconLimits {
    pub max_timestamps: usize,
    pub min_events: usize,
    pub min_median_seconds: i64,
}


impl Default for BeaconLimits {
    fn default() -> Self {
        Self {
            max_timestamps: DEFAULT_MAX_TIMESTAMPS,
            min_events: DEFAULT_MIN_EVENTS,
            min_median_seconds: DEFAULT_MIN_MEDIAN_SECONDS,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconScore {
    pub events: usize,
    pub median_interval: i128,
    pub mad: i128,
    pub regularity_ppm: i128,
}
