//! Read-only PostgreSQL queries and the strict parse of their `psql -X -A --csv -t` output.

use crate::error::NtpError;
use crate::grammar::is_application_name;
use crate::limits::{MAX_ACTIVITY_ROWS, MAX_REPLICATION_ROWS, MAX_SETTINGS_ROWS};
use crate::model::{PgActivity, PgConnections, PgReplica, PgReplication, PgSettings, ReplicaState};
use crate::parse::read_bounded;
use crate::units::count;
use std::io::Read;


const SETTINGS_COLUMNS: usize = 3;


const REPLICATION_COLUMNS: usize = 3;


/// Flags of every run: `psql -X -A --csv -t -c <query>`.
pub const PSQL_FLAGS: [&str; 5] = ["-X", "-A", "--csv", "-t", "-c"];


pub const PG_SETTINGS_SQL: &str = "SELECT current_setting('max_connections')::int, pg_is_in_recovery(), current_setting('server_version_num')::int";


pub const PG_CONNECTIONS_SQL: &str = "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'";


pub const PG_ACTIVITY_SQL: &str = "SELECT greatest(0, (extract(epoch FROM clock_timestamp() - query_start) * 1000)::bigint) \
FROM pg_stat_activity WHERE backend_type = 'client backend' AND state = 'active' AND pid <> pg_backend_pid() ORDER BY 1 DESC LIMIT 1000";


pub const PG_REPLICATION_SQL: &str = "SELECT CASE WHEN application_name ~ '^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$' THEN application_name END, state, \
(extract(epoch FROM replay_lag) * 1000)::bigint FROM pg_stat_replication LIMIT 256";


fn rows(text: &str, cap: usize) -> Result<Vec<&str>, NtpError> {
    let lines = text.split_terminator('\n');
    if lines.clone().take(cap.saturating_add(1)).count() > cap {
        Err(NtpError::TooManyRows { limit: cap })
    } else {
        Ok(lines.collect())
    }
}


fn columns<const WIDTH: usize>(line: &str) -> Result<[&str; WIDTH], NtpError> {
    let fields: Vec<&str> = line.split(',').take(WIDTH.saturating_add(1)).collect();
    <[&str; WIDTH]>::try_from(fields).map_err(|_| NtpError::Malformed {
        reason: "wrong column count",
    })
}


fn flag(text: &str) -> Result<bool, NtpError> {
    match text {
        "t" => Ok(true),
        "f" => Ok(false),
        _ => Err(NtpError::Malformed { reason: "bad boolean" }),
    }
}


fn millis(text: &str) -> Result<u64, NtpError> {
    let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    digits
        .then_some(text)
        .and_then(|digits_only| digits_only.parse::<u64>().ok())
        .ok_or(NtpError::Malformed { reason: "bad milliseconds" })
}


fn replica_state(text: &str) -> Option<ReplicaState> {
    match text {
        "startup" => Some(ReplicaState::Startup),
        "catchup" => Some(ReplicaState::Catchup),
        "streaming" => Some(ReplicaState::Streaming),
        "backup" => Some(ReplicaState::Backup),
        "stopping" => Some(ReplicaState::Stopping),
        _ => None,
    }
}


/// One row: `max_connections,in_recovery(t|f),server_version_num`.
pub fn parse_pg_settings<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<PgSettings, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let lines = rows(&text, MAX_SETTINGS_ROWS)?;
    let line = lines.first().ok_or(NtpError::Malformed { reason: "no row" })?;
    let [max_connections, in_recovery, version_num] = columns::<SETTINGS_COLUMNS>(line)?;
    Ok(PgSettings {
        max_connections: count(max_connections)?,
        in_recovery: flag(in_recovery)?,
        version_num: count(version_num)?,
    })
}


/// One row: the count of client backends.
pub fn parse_pg_connections<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<PgConnections, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let lines = rows(&text, MAX_SETTINGS_ROWS)?;
    let line = lines.first().ok_or(NtpError::Malformed { reason: "no row" })?;
    let [client_backends] = columns::<1>(line)?;
    Ok(PgConnections {
        client_backends: count(client_backends)?,
    })
}


/// Zero or more rows of one duration in milliseconds; exactly `MAX_ACTIVITY_ROWS` rows is `at_least`.
pub fn parse_pg_activity<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<PgActivity, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let durations_ms = rows(&text, MAX_ACTIVITY_ROWS)?
        .into_iter()
        .map(|line| columns::<1>(line).and_then(|[duration]| millis(duration)))
        .collect::<Result<Vec<u64>, NtpError>>()?;
    let at_least = durations_ms.len() == MAX_ACTIVITY_ROWS;
    Ok(PgActivity { durations_ms, at_least })
}


fn replica(line: &str) -> Result<PgReplica, NtpError> {
    let [name, state, lag] = columns::<REPLICATION_COLUMNS>(line)?;
    Ok(PgReplica {
        application_name: Some(name).filter(|candidate| is_application_name(candidate)).map(str::to_string),
        state: replica_state(state),
        replay_lag_ms: Some(lag).filter(|text| !text.is_empty()).map(millis).transpose()?,
    })
}


/// Zero or more rows `application_name,state,replay_lag_ms`; an unlisted name or state is `None` and counted.
pub fn parse_pg_replication<Input: Read>(mut reader: Input, max_bytes: u64) -> Result<PgReplication, NtpError> {
    let text = read_bounded(&mut reader, max_bytes)?;
    let replicas = rows(&text, MAX_REPLICATION_ROWS)?
        .into_iter()
        .map(replica)
        .collect::<Result<Vec<PgReplica>, NtpError>>()?;
    let rejected_names = replicas.iter().filter(|item| item.application_name.is_none()).count();
    let unknown_values = replicas.iter().filter(|item| item.state.is_none()).count();
    Ok(PgReplication {
        replicas,
        rejected_names,
        unknown_values,
    })
}
