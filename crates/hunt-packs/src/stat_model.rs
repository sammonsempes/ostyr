use crate::model::{Baseline, Cost, HuntPack, Source};
use crate::packs::{
    bytes_read_ok, is_pack_id, params_ok, query_ok, MAX_ROWS_CEILING, MAX_SCHEDULE_SECONDS, MAX_SECONDS_CEILING, MAX_WINDOW_SECONDS,
    MIN_SCHEDULE_SECONDS, MIN_WINDOW_SECONDS,
};
use crate::run::HuntOutcome;
use serde::Deserialize;
use std::collections::BTreeSet;


pub const MAX_STAT_HUNTS: usize = 32;


pub const MAX_STAT_ID_CHARS: usize = 40;


pub const MAX_STAT_ROWS: u32 = 50_000;


pub const MAX_ENTITIES_CEILING: usize = 10_000;


pub const PPM_CEILING: u32 = 1_000_000;


pub const BOUND_SUFFIX: &str = ".bound";


pub const STAT_TECHNIQUE: &str = "T0000";


/// The statistic and its one parameter: `rarity` keeps keys seen on at most `max_entities` entities, `beaconing` counts the entities whose events have a regularity of at least `min_regularity_ppm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Statistic {
    Rarity { max_entities: usize },
    Beaconing { min_regularity_ppm: u32 },
}


/// A statistical hunt of `hunt.yaml`: the query returns two columns per row (entity and key for rarity, entity and unix seconds for beaconing), at most `max_rows` rows; a finding is stored when the match count is above `max_matches`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatHunt {
    pub id: String,
    pub statistic: Statistic,
    pub query: String,
    pub schedule_seconds: u64,
    pub window_seconds: u64,
    pub cost: Cost,
    pub max_rows: u32,
    #[serde(default)]
    pub max_matches: u64,
}


pub fn kind_name(statistic: &Statistic) -> &'static str {
    match statistic {
        Statistic::Rarity { .. } => "rarity",
        Statistic::Beaconing { .. } => "beaconing",
    }
}


/// The id the scheduler, the run state and the findings use: the statistic, a dot, the declared id.
pub fn stat_pack_id(hunt: &StatHunt) -> String {
    format!("{}.{}", kind_name(&hunt.statistic), hunt.id)
}


/// The id of the finding that says the input went over `max_rows`.
pub fn bound_id(pack_id: &str) -> String {
    format!("{pack_id}{BOUND_SUFFIX}")
}


/// The scheduling view of a statistical hunt: the same fields a pack has, so the tick, the run state and the store need no second path.
pub fn stat_pack(hunt: &StatHunt) -> HuntPack {
    HuntPack {
        id: stat_pack_id(hunt),
        title: hunt.id.clone(),
        hypothesis: kind_name(&hunt.statistic).to_owned(),
        technique: STAT_TECHNIQUE.to_owned(),
        source: Source::Clickhouse,
        query: hunt.query.clone(),
        schedule_seconds: hunt.schedule_seconds,
        window_seconds: hunt.window_seconds,
        cost: hunt.cost.clone(),
        baseline: Baseline {
            max_matches: hunt.max_matches,
        },
        tests: Vec::new(),
    }
}


/// The finding to store for an outcome: the hunt's own id, or the bound id with the bound as baseline.
pub fn finding_of(pack: &HuntPack, outcome: &HuntOutcome) -> (String, u64, u64) {
    outcome.bound.map_or_else(
        || (pack.id.clone(), outcome.matches, pack.baseline.max_matches),
        |limit| (bound_id(&pack.id), outcome.matches, limit),
    )
}


pub fn parameter_ok(statistic: &Statistic) -> bool {
    match statistic {
        Statistic::Rarity { max_entities } => (1..=MAX_ENTITIES_CEILING).contains(max_entities),
        Statistic::Beaconing { min_regularity_ppm } => (1..=PPM_CEILING).contains(min_regularity_ppm),
    }
}


/// The first invalid field of one statistical hunt, or none.
pub fn invalid_field(hunt: &StatHunt) -> Option<&'static str> {
    let checks = [
        ("id", is_pack_id(&hunt.id) && hunt.id.len() <= MAX_STAT_ID_CHARS),
        ("statistic", parameter_ok(&hunt.statistic)),
        ("query", query_ok(&hunt.query) && params_ok(&hunt.query)),
        (
            "schedule_seconds",
            (MIN_SCHEDULE_SECONDS..=MAX_SCHEDULE_SECONDS).contains(&hunt.schedule_seconds),
        ),
        ("window_seconds", (MIN_WINDOW_SECONDS..=MAX_WINDOW_SECONDS).contains(&hunt.window_seconds)),
        ("window_seconds", hunt.window_seconds >= hunt.schedule_seconds),
        ("cost.max_rows", (1..=MAX_ROWS_CEILING).contains(&hunt.cost.max_rows)),
        ("cost.max_seconds", (1..=MAX_SECONDS_CEILING).contains(&hunt.cost.max_seconds)),
        ("cost.max_bytes_read", bytes_read_ok(Source::Clickhouse, hunt.cost.max_bytes_read)),
        ("max_rows", (1..=MAX_STAT_ROWS).contains(&hunt.max_rows)),
        ("max_matches", hunt.max_matches <= MAX_ROWS_CEILING),
    ];
    checks.iter().find(|check| !check.1).map(|check| check.0)
}


/// The first invalid field over the whole list, or a duplicate id or an over-long list.
pub fn validate_stat_hunts(hunts: &[StatHunt]) -> Result<(), &'static str> {
    (hunts.len() <= MAX_STAT_HUNTS).then_some(()).ok_or("stat_hunts")?;
    hunts.iter().try_fold(BTreeSet::new(), |mut seen, hunt| {
        invalid_field(hunt).map_or(Ok(()), Err)?;
        seen.insert(stat_pack_id(hunt)).then_some(seen).ok_or("id")
    })?;
    Ok(())
}


/// The statistical hunts as packs, minus those whose scheduler id a file pack already holds; the second value counts the dropped ones.
pub fn merge_stat_packs(packs: Vec<HuntPack>, hunts: &[StatHunt]) -> (Vec<HuntPack>, usize) {
    let taken: BTreeSet<String> = packs.iter().map(|pack| pack.id.clone()).collect();
    let (kept, dropped): (Vec<HuntPack>, Vec<HuntPack>) = hunts.iter().map(stat_pack).partition(|pack| !taken.contains(&pack.id));
    let refused = dropped.len();
    (packs.into_iter().chain(kept).collect(), refused)
}
