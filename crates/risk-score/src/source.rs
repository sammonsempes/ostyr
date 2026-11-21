use crate::error::RiskError;
use crate::model::{Contribution, EntityKind, EntityRef, Score, Severity, Weights};
use crate::score::{check_contribution, score_entities, DECAY_DAYS, MAX_CONTRIBUTIONS, MAX_ENTITIES, PER_MILLION, SECONDS_PER_DAY};
use alerts::error::StoreError;
use alerts::model::Severity as AlertSeverity;
use alerts::store::{cell, entity, number};
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, BTreeSet};


/// Alerts of one tenant newer than `$2`, oldest first, through `alerts_by_created`, with the triage status (empty when none) joined on its key.
pub const RISK_ALERTS_SQL: &str = "SELECT alerts.id, alerts.rule_id, alerts.severity, alerts.created::text, COALESCE(alerts.host_name, ''), \
                                   COALESCE(alerts.user_name, ''), COALESCE(alert_triage.status, '') FROM alerts \
                                   LEFT JOIN alert_triage ON alert_triage.tenant = alerts.tenant AND alert_triage.alert_id = alerts.id \
                                   WHERE alerts.tenant = $1 AND alerts.created > $2::text::bigint ORDER BY alerts.created, alerts.id \
                                   LIMIT $3::text::bigint";


/// As `RISK_ALERTS_SQL` after the keyset `($3, $4)` = (created, id) of the last alert of the previous page.
pub const RISK_ALERTS_NEXT_SQL: &str = "SELECT alerts.id, alerts.rule_id, alerts.severity, alerts.created::text, COALESCE(alerts.host_name, ''), \
                                        COALESCE(alerts.user_name, ''), COALESCE(alert_triage.status, '') FROM alerts \
                                        LEFT JOIN alert_triage ON alert_triage.tenant = alerts.tenant AND alert_triage.alert_id = alerts.id \
                                        WHERE alerts.tenant = $1 AND alerts.created > $2::text::bigint \
                                        AND (alerts.created, alerts.id) > ($3::text::bigint, $4::text) \
                                        ORDER BY alerts.created, alerts.id LIMIT $5::text::bigint";


pub const PAGE_SIZE: usize = 1_000;


pub const MAX_ALERTS: usize = 200_000;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const ID_COLUMN: usize = 0;


pub const RULE_COLUMN: usize = 1;


pub const SEVERITY_COLUMN: usize = 2;


pub const CREATED_COLUMN: usize = 3;


pub const HOST_COLUMN: usize = 4;


pub const USER_COLUMN: usize = 5;


pub const STATUS_COLUMN: usize = 6;


pub const FALSE_POSITIVE_STATUS: &str = "false_positive";


pub const CLOSED_STATUS: &str = "closed";


pub const ACKNOWLEDGED_STATUS: &str = "acknowledged";


pub const MIN_VERDICTS: u64 = 20;


pub const MIN_FP_HOSTS: usize = 3;


pub const MIN_FP_DAYS: usize = 3;


pub const MAX_FP_RATE_PPM: u32 = 900_000;


pub const MAX_NAMED_FP_RULES: usize = 100;


pub const MICROS_PER_DAY: u64 = 86_400_000_000;


pub const ENTITY_COLUMNS: [(EntityKind, usize); 2] = [(EntityKind::Host, HOST_COLUMN), (EntityKind::User, USER_COLUMN)];


pub const EXTRA_PAGES: usize = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub page_size: usize,
    pub max_alerts: usize,
    pub max_contributions: usize,
    pub max_entities: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Limits {
            page_size: PAGE_SIZE,
            max_alerts: MAX_ALERTS,
            max_contributions: MAX_CONTRIBUTIONS,
            max_entities: MAX_ENTITIES,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Alerts,
    Contributions,
    Entities,
}


/// The read stopped at `cap` of the named bound, with `read` of them held; the scores cover only what was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    pub limit: Limit,
    pub read: usize,
    pub cap: usize,
}


/// The verdicts read for one rule: counts, and the first hosts and days (at most the floors) of its false positives.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Verdicts {
    pub false_positive: u64,
    pub closed: u64,
    pub hosts: BTreeSet<String>,
    pub days: BTreeSet<u64>,
}


/// A rule whose false-positive rate is applied; `capped` when the raw rate went above `MAX_FP_RATE_PPM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpRule {
    pub rule_id: String,
    pub false_positive: u64,
    pub closed: u64,
    pub rate_ppm: u32,
    pub capped: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub scores: Vec<Score>,
    pub alerts_read: usize,
    pub informational: usize,
    pub refused: BTreeMap<EntityKind, usize>,
    pub truncated: Option<Truncated>,
    pub fp_rules: Vec<FpRule>,
    pub fp_rules_omitted: usize,
    pub unknown_verdicts: usize,
}


#[derive(Default)]
pub struct Gathered {
    pub contributions: Vec<Contribution>,
    pub entities: BTreeSet<EntityRef>,
    pub alerts_read: usize,
    pub informational: usize,
    pub refused: BTreeMap<EntityKind, usize>,
    pub truncated: Option<Truncated>,
    pub verdicts: BTreeMap<String, Verdicts>,
    pub unknown_verdicts: usize,
}


/// Microseconds of the oldest alert still inside the decay window; an alert exactly this old counts 0 and is excluded.
pub fn window_start_micros(now: i64) -> i64 {
    now.saturating_sub(DECAY_DAYS * SECONDS_PER_DAY)
        .max(0)
        .saturating_mul(MICROS_PER_SECOND.cast_signed())
}


pub fn risk_severity(severity: AlertSeverity) -> Option<Severity> {
    match severity {
        AlertSeverity::Informational => None,
        AlertSeverity::Low => Some(Severity::Low),
        AlertSeverity::Medium => Some(Severity::Medium),
        AlertSeverity::High => Some(Severity::High),
        AlertSeverity::Critical => Some(Severity::Critical),
    }
}


pub fn per_million(part: u64, whole: u64) -> u32 {
    let scaled = part.saturating_mul(u64::from(PER_MILLION));
    scaled.checked_div(whole).map_or(0, |rate| rate.min(u64::from(PER_MILLION)) as u32)
}


/// `(fleet_rate, entity_rate)` of every contribution, over the contributions given only.
pub fn rates_of(contributions: &[Contribution]) -> Vec<(u32, u32)> {
    let mut entity_alerts: BTreeMap<&EntityRef, u64> = BTreeMap::new();
    let mut entity_rule_alerts: BTreeMap<(&EntityRef, &str), u64> = BTreeMap::new();
    let mut rule_entities: BTreeMap<&str, u64> = BTreeMap::new();
    for contribution in contributions {
        *entity_alerts.entry(&contribution.entity).or_default() += 1;
        let pair = entity_rule_alerts
            .entry((&contribution.entity, contribution.rule_id.as_str()))
            .or_default();
        *rule_entities.entry(contribution.rule_id.as_str()).or_default() += u64::from(*pair == 0);
        *pair += 1;
    }
    let fleet_entities = entity_alerts.len() as u64;
    contributions
        .iter()
        .map(|contribution| {
            let with_rule = rule_entities.get(contribution.rule_id.as_str()).copied().unwrap_or(0);
            let on_entity = entity_alerts.get(&contribution.entity).copied().unwrap_or(0);
            let of_rule = entity_rule_alerts
                .get(&(&contribution.entity, contribution.rule_id.as_str()))
                .copied()
                .unwrap_or(0);
            (per_million(with_rule, fleet_entities), per_million(of_rule, on_entity))
        })
        .collect()
}


pub fn with_rates(contributions: Vec<Contribution>) -> Vec<Contribution> {
    let rates = rates_of(&contributions);
    contributions
        .into_iter()
        .zip(rates)
        .map(|(contribution, (fleet_rate, entity_rate))| Contribution {
            fleet_rate,
            entity_rate,
            ..contribution
        })
        .collect()
}


/// One contribution per present, accepted entity of the alert; a refused entity is counted by kind and the other one still counts.
pub fn candidates(gathered: &mut Gathered, row: &Row, severity: Severity) -> Result<Vec<Contribution>, StoreError> {
    let created_micros = cell(row, CREATED_COLUMN)?.parse::<u64>().map_err(|source| StoreError::BadNumber {
        column: CREATED_COLUMN,
        source,
    })?;
    let observed_at = (created_micros / MICROS_PER_SECOND).cast_signed();
    let rule_id = cell(row, RULE_COLUMN)?;
    let mut accepted = Vec::new();
    for (kind, column) in ENTITY_COLUMNS {
        if let Some(id) = entity(row, column)? {
            let contribution = Contribution {
                entity: EntityRef { kind, id },
                rule_id: rule_id.to_owned(),
                severity,
                observed_at,
                fleet_rate: 0,
                entity_rate: 0,
                false_positive_rate: 0,
            };
            match check_contribution(&contribution) {
                Ok(()) => accepted.push(contribution),
                Err(_refused) => *gathered.refused.entry(kind).or_default() += 1,
            }
        }
    }
    Ok(accepted)
}


/// Counts the triage status of an alert read: false positives and closes per rule, an unknown text apart; other statuses are no verdict.
pub fn tally_verdict(gathered: &mut Gathered, row: &Row) -> Result<(), StoreError> {
    let status = cell(row, STATUS_COLUMN)?;
    if status == FALSE_POSITIVE_STATUS || status == CLOSED_STATUS {
        let rule_id = cell(row, RULE_COLUMN)?;
        let created_micros = number(row, CREATED_COLUMN)?;
        let host = cell(row, HOST_COLUMN)?;
        let verdicts = gathered.verdicts.entry(rule_id.to_owned()).or_default();
        if status == CLOSED_STATUS {
            verdicts.closed += 1;
        } else {
            verdicts.false_positive += 1;
            if !host.is_empty() && verdicts.hosts.len() < MIN_FP_HOSTS {
                verdicts.hosts.insert(host.to_owned());
            }
            if verdicts.days.len() < MIN_FP_DAYS {
                verdicts.days.insert(created_micros / MICROS_PER_DAY);
            }
        }
    } else if !status.is_empty() && status != ACKNOWLEDGED_STATUS {
        gathered.unknown_verdicts += 1;
    }
    Ok(())
}


/// The rate of a rule in parts per million, 0 below the floors (verdicts, hosts, days), and whether it was cut at `MAX_FP_RATE_PPM`.
pub fn fp_rate(verdicts: &Verdicts) -> (u32, bool) {
    let total = verdicts.false_positive + verdicts.closed;
    let enough = total >= MIN_VERDICTS && verdicts.hosts.len() >= MIN_FP_HOSTS && verdicts.days.len() >= MIN_FP_DAYS;
    let raw = if enough { per_million(verdicts.false_positive, total) } else { 0 };
    (raw.min(MAX_FP_RATE_PPM), raw > MAX_FP_RATE_PPM)
}


/// The rules with an applied rate above 0, highest rate first then rule id, and how many the cut at `MAX_NAMED_FP_RULES` left out.
pub fn fp_rules_of(verdicts: &BTreeMap<String, Verdicts>) -> (Vec<FpRule>, usize) {
    let mut rules: Vec<FpRule> = verdicts
        .iter()
        .filter_map(|(rule_id, counted)| {
            let (rate_ppm, capped) = fp_rate(counted);
            (rate_ppm > 0).then(|| FpRule {
                rule_id: rule_id.clone(),
                false_positive: counted.false_positive,
                closed: counted.closed,
                rate_ppm,
                capped,
            })
        })
        .collect();
    rules.sort_by(|left, right| right.rate_ppm.cmp(&left.rate_ppm).then_with(|| left.rule_id.cmp(&right.rule_id)));
    let omitted = rules.len().saturating_sub(MAX_NAMED_FP_RULES);
    rules.truncate(MAX_NAMED_FP_RULES);
    (rules, omitted)
}


/// Sets each non-critical contribution's false-positive rate from its rule's verdicts; a critical one keeps 0.
pub fn with_false_positive_rates(contributions: Vec<Contribution>, verdicts: &BTreeMap<String, Verdicts>) -> Vec<Contribution> {
    contributions
        .into_iter()
        .map(|contribution| {
            let rate = verdicts.get(&contribution.rule_id).map_or(0, |counted| fp_rate(counted).0);
            Contribution {
                false_positive_rate: if contribution.severity == Severity::Critical { 0 } else { rate },
                ..contribution
            }
        })
        .collect()
}


/// Adds one alert, or records which bound it would break; nothing is added once a bound is hit.
pub fn absorb(gathered: &mut Gathered, limits: &Limits, row: &Row) -> Result<(), StoreError> {
    if gathered.alerts_read >= limits.max_alerts {
        gathered.truncated = Some(Truncated {
            limit: Limit::Alerts,
            read: gathered.alerts_read,
            cap: limits.max_alerts,
        });
    } else {
        match risk_severity(cell(row, SEVERITY_COLUMN)?.parse::<AlertSeverity>()?) {
            None => gathered.informational += 1,
            Some(severity) => {
                let accepted = candidates(gathered, row, severity)?;
                let fresh = accepted
                    .iter()
                    .filter(|contribution| !gathered.entities.contains(&contribution.entity))
                    .count();
                if gathered.contributions.len() + accepted.len() > limits.max_contributions {
                    gathered.truncated = Some(Truncated {
                        limit: Limit::Contributions,
                        read: gathered.contributions.len(),
                        cap: limits.max_contributions,
                    });
                } else if gathered.entities.len() + fresh > limits.max_entities {
                    gathered.truncated = Some(Truncated {
                        limit: Limit::Entities,
                        read: gathered.entities.len(),
                        cap: limits.max_entities,
                    });
                } else {
                    gathered.entities.extend(accepted.iter().map(|contribution| contribution.entity.clone()));
                    gathered.contributions.extend(accepted);
                }
            }
        }
    }
    if gathered.truncated.is_none() {
        gathered.alerts_read += 1;
        tally_verdict(gathered, row)?;
    }
    Ok(())
}


/// The `(created, id)` keyset position of an alert row.
pub fn position(row: &Row) -> Result<(String, String), StoreError> {
    Ok((cell(row, CREATED_COLUMN)?.to_owned(), cell(row, ID_COLUMN)?.to_owned()))
}


pub async fn fetch_page(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    lower: &str,
    after: Option<&(String, String)>,
    page_size: usize,
) -> Result<Vec<Row>, StoreError> {
    let size = page_size.to_string();
    let rows = match after {
        None => exec(scope.clone(), RISK_ALERTS_SQL, vec![lower.to_owned(), size]).await?,
        Some((created, id)) => {
            exec(
                scope.clone(),
                RISK_ALERTS_NEXT_SQL,
                vec![lower.to_owned(), created.clone(), id.clone(), size],
            )
            .await?
        }
    };
    Ok(rows)
}


/// Reads the tenant's alerts of the decay window page by page, stopping loudly at the first bound, and scores the entities they name.
pub async fn tenant_scores(exec: Executor<'_, '_>, scope: &TenantScope, weights: &Weights, now: i64, limits: &Limits) -> Result<Outcome, RiskError> {
    let lower = window_start_micros(now).to_string();
    let page_size = limits.page_size.max(1);
    let mut gathered = Gathered::default();
    let mut after: Option<(String, String)> = None;
    let mut done = false;
    for _page in 0..limits.max_alerts / page_size + EXTRA_PAGES {
        if !done {
            let rows = fetch_page(exec, scope, &lower, after.as_ref(), page_size).await?;
            for row in &rows {
                if gathered.truncated.is_none() {
                    absorb(&mut gathered, limits, row)?;
                }
            }
            after = rows.last().map(position).transpose()?;
            done = rows.len() < page_size || gathered.truncated.is_some();
        }
    }
    let contributions = with_false_positive_rates(with_rates(gathered.contributions), &gathered.verdicts);
    let (fp_rules, fp_rules_omitted) = fp_rules_of(&gathered.verdicts);
    let scores = score_entities(&contributions, weights, now)?;
    Ok(Outcome {
        scores,
        alerts_read: gathered.alerts_read,
        informational: gathered.informational,
        refused: gathered.refused,
        truncated: gathered.truncated,
        fp_rules,
        fp_rules_omitted,
        unknown_verdicts: gathered.unknown_verdicts,
    })
}
