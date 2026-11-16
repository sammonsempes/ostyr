use serde::Deserialize;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityKind {
    User,
    Host,
    Ip,
    Container,
    CloudAccount,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityRef {
    pub kind: EntityKind,
    pub id: String,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}


/// Rates are integer counts per million; `observed_at` is Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    pub entity: EntityRef,
    pub rule_id: String,
    pub severity: Severity,
    pub observed_at: i64,
    pub fleet_rate: u32,
    pub entity_rate: u32,
    pub false_positive_rate: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityPoints {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub severity_points: SeverityPoints,
    pub rare_threshold_per_million: u32,
    pub entity_rare_bonus_permille: u32,
    pub fleet_rare_bonus_permille: u32,
    pub full_score_points: u32,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Score {
    pub entity: EntityRef,
    pub value: u8,
    pub contributions_used: usize,
    pub contributions_dropped: usize,
}
