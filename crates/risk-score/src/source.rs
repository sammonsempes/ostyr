use crate::error::RiskError;
use crate::model::{Contribution, EntityKind, EntityRef, Score, Severity, Weights};
use crate::score::{check_contribution, score_entities, DECAY_DAYS, MAX_CONTRIBUTIONS, MAX_ENTITIES, PER_MILLION, SECONDS_PER_DAY};
use alerts::error::StoreError;
use alerts::model::Severity as AlertSeverity;
use alerts::store::{cell, entity};
use alerts::types::{Executor, Row};
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, BTreeSet};


/// Alerts of one tenant newer than `$2`, oldest first, through `alerts_by_created`; the keyset needs `id`, no other column is read.
pub const RISK_ALERTS_SQL: &str = "SELECT id, rule_id, severity, created::text, COALESCE(host_name, ''), COALESCE(user_name, '') FROM alerts \
                                   WHERE tenant = $1 AND created > $2::text::bigint ORDER BY alerts.created, alerts.id LIMIT $3::text::bigint";


/// As `RISK_ALERTS_SQL` after the keyset `($3, $4)` = (created, id) of the last alert of the previous page.
pub const RISK_ALERTS_NEXT_SQL: &str = "SELECT id, rule_id, severity, created::text, COALESCE(host_name, ''), COALESCE(user_name, '') FROM alerts \
                                        WHERE tenant = $1 AND created > $2::text::bigint AND (created, id) > ($3::text::bigint, $4::text) \
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


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub scores: Vec<Score>,
    pub alerts_read: usize,
    pub informational: usize,
    pub refused: BTreeMap<EntityKind, usize>,
    pub truncated: Option<Truncated>,
}


#[derive(Default)]
pub struct Gathered {
    pub contributions: Vec<Contribution>,
    pub entities: BTreeSet<EntityRef>,
    pub alerts_read: usize,
    pub informational: usize,
    pub refused: BTreeMap<EntityKind, usize>,
    pub truncated: Option<Truncated>,
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
    gathered.alerts_read += usize::from(gathered.truncated.is_none());
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
    let contributions = with_rates(gathered.contributions);
    let scores = score_entities(&contributions, weights, now)?;
    Ok(Outcome {
        scores,
        alerts_read: gathered.alerts_read,
        informational: gathered.informational,
        refused: gathered.refused,
        truncated: gathered.truncated,
    })
}
