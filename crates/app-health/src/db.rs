//! Database expectations file, the verdict on one database and its measures.

use crate::error::NtpError;
use crate::grammar::is_db_name;
use crate::limits::{MAX_DATABASES, MAX_DB_MS, MAX_EXPECTATIONS_BYTES, MAX_MIN_REPLICAS, MAX_RATIO_LIMIT, MIN_RATIO_EXCLUSIVE, MIN_SLOW_QUERY_MS};
use crate::model::{
    DbExpectation, DbExpectationsFile, DbHealth, DbRole, Measure, PgActivity, PgConnections, PgReplication, PgSettings, ReplicaState,
};
use core_config::parse::parse_document;


pub fn load_db_expectations(text: &str, file: &str) -> Result<Vec<DbExpectation>, NtpError> {
    if text.len() > MAX_EXPECTATIONS_BYTES {
        Err(NtpError::Oversized {
            limit: MAX_EXPECTATIONS_BYTES as u64,
        })
    } else {
        let document: DbExpectationsFile = parse_document(text, file)?;
        if document.databases.len() > MAX_DATABASES {
            Err(NtpError::OutOfRange { field: "databases" })
        } else {
            document.databases.iter().try_for_each(check_db)?;
            Ok(document.databases)
        }
    }
}


fn check_db(expectation: &DbExpectation) -> Result<(), NtpError> {
    let ratio = expectation.max_connections_ratio;
    if !is_db_name(&expectation.name) {
        Err(NtpError::OutOfRange { field: "name" })
    } else if !(ratio > MIN_RATIO_EXCLUSIVE && ratio <= MAX_RATIO_LIMIT) {
        Err(NtpError::OutOfRange {
            field: "max_connections_ratio",
        })
    } else if !(MIN_SLOW_QUERY_MS..=MAX_DB_MS).contains(&expectation.slow_query_ms) {
        Err(NtpError::OutOfRange { field: "slow_query_ms" })
    } else if expectation.max_replay_lag_ms > MAX_DB_MS {
        Err(NtpError::OutOfRange { field: "max_replay_lag_ms" })
    } else if expectation.min_replicas > MAX_MIN_REPLICAS {
        Err(NtpError::OutOfRange { field: "min_replicas" })
    } else {
        Ok(())
    }
}


/// Active client queries strictly longer than `slow_query_ms`.
pub fn slow_count(expectation: &DbExpectation, activity: &PgActivity) -> usize {
    activity
        .durations_ms
        .iter()
        .filter(|duration| **duration > expectation.slow_query_ms)
        .count()
}


/// Rows in state `streaming`.
pub fn streaming_count(replication: &PgReplication) -> usize {
    replication
        .replicas
        .iter()
        .filter(|item| item.state == Some(ReplicaState::Streaming))
        .count()
}


/// Rows whose lag is unknown: an empty lag on any state but `streaming`.
pub fn unknown_lags(replication: &PgReplication) -> usize {
    replication
        .replicas
        .iter()
        .filter(|item| item.replay_lag_ms.is_none() && item.state != Some(ReplicaState::Streaming))
        .count()
}


/// Largest known replay lag; an empty lag on a `streaming` row is zero, an empty lag elsewhere is skipped.
pub fn max_lag(replication: &PgReplication) -> Option<u64> {
    replication
        .replicas
        .iter()
        .filter_map(|item| item.replay_lag_ms.or_else(|| (item.state == Some(ReplicaState::Streaming)).then_some(0)))
        .max()
}


fn wrong_role(role: DbRole, settings: &PgSettings) -> bool {
    match role {
        DbRole::Primary => settings.in_recovery,
        DbRole::Replica => !settings.in_recovery,
        DbRole::Unconstrained => false,
    }
}


/// Precedence: BlindSpot (an input missing) > WrongRole > ReplicaMissing > ReplicationLag > Saturated > SlowQueries > Healthy.
pub fn assess_db(
    expectation: &DbExpectation,
    settings: Option<&PgSettings>,
    connections: Option<&PgConnections>,
    activity: Option<&PgActivity>,
    replication: Option<&PgReplication>,
) -> DbHealth {
    match (settings, connections, activity, replication) {
        (Some(known_settings), Some(known_connections), Some(known_activity), Some(known_replication)) => {
            assess_known(expectation, known_settings, known_connections, known_activity, known_replication)
        }
        _ => DbHealth::BlindSpot,
    }
}


fn assess_known(
    expectation: &DbExpectation,
    settings: &PgSettings,
    connections: &PgConnections,
    activity: &PgActivity,
    replication: &PgReplication,
) -> DbHealth {
    let limit = expectation.max_connections_ratio * f64::from(settings.max_connections);
    let lagging = max_lag(replication).filter(|lag| *lag > expectation.max_replay_lag_ms);
    let slow = slow_count(expectation, activity);
    if wrong_role(expectation.role, settings) {
        DbHealth::WrongRole
    } else if streaming_count(replication) < usize::try_from(expectation.min_replicas).unwrap_or(usize::MAX) {
        DbHealth::ReplicaMissing
    } else if let Some(lag_ms) = lagging {
        DbHealth::ReplicationLag { lag_ms }
    } else if f64::from(connections.client_backends) > limit {
        DbHealth::Saturated {
            connections: connections.client_backends,
        }
    } else if slow > 0 {
        DbHealth::SlowQueries { count: slow }
    } else {
        DbHealth::Healthy
    }
}


/// Connections, active and slow queries, largest replay lag, unknown lags; an unavailable value gives no measure, never 0.
pub fn db_measures(
    expectation: &DbExpectation,
    connections: Option<&PgConnections>,
    activity: Option<&PgActivity>,
    replication: Option<&PgReplication>,
) -> Vec<Measure> {
    let candidates = [
        ("db.connections", "1", connections.map(|item| f64::from(item.client_backends))),
        ("db.active_queries", "1", activity.map(|item| item.durations_ms.len() as f64)),
        ("db.slow_queries", "1", activity.map(|item| slow_count(expectation, item) as f64)),
        ("db.replay_lag_max", "ms", replication.and_then(max_lag).map(|lag| lag as f64)),
        ("db.replay_lag_unknown", "1", replication.map(|item| unknown_lags(item) as f64)),
    ];
    candidates
        .iter()
        .filter_map(|(name, unit, value)| value.map(|found| Measure { name, unit, value: found }))
        .collect()
}
