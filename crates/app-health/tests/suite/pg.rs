use crate::suite::common::TestResult;
use app_health::error::NtpError;
use app_health::model::ReplicaState;
use app_health::pg::{
    parse_pg_activity, parse_pg_connections, parse_pg_replication, parse_pg_settings, PG_ACTIVITY_SQL, PG_CONNECTIONS_SQL, PG_REPLICATION_SQL,
    PG_SETTINGS_SQL, PSQL_FLAGS,
};
use std::io::Read;


const MAX_CSV: u64 = 65_536;


const ACTIVITY_CAP: usize = 1000;


const REPLICATION_CAP: usize = 256;


const SMALL_CAP: u64 = 8;


const MAX_CONNECTIONS: u32 = 100;


const VERSION: u32 = 160_004;


const LAG_MS: u64 = 1500;


const LONG_NAME_CHARS: usize = 65;


const NAME_CHARS: usize = 64;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const SEVEN: u32 = 7;


const SLOW_ROW_MS: u64 = 8001;


const FAST_ROW_MS: u64 = 5;


const TWO_REPLICAS: usize = 2;


const REJECTED_NAMES: usize = 5;


const ROW_MS: &str = "5";


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


fn rows_of(line: &str, count: usize) -> String {
    format!("{line}\n").repeat(count)
}


#[test]
fn queries_are_read_only_and_bounded() -> TestResult {
    let all = [PG_SETTINGS_SQL, PG_CONNECTIONS_SQL, PG_ACTIVITY_SQL, PG_REPLICATION_SQL];
    assert!(all.iter().all(|sql| sql.starts_with("SELECT ")));
    assert!(all.iter().all(|sql| !sql.contains(';')));
    assert!(PG_ACTIVITY_SQL.ends_with(&format!("LIMIT {ACTIVITY_CAP}")));
    assert!(PG_REPLICATION_SQL.ends_with(&format!("LIMIT {REPLICATION_CAP}")));
    assert_eq!(PSQL_FLAGS, ["-X", "-A", "--csv", "-t", "-c"]);
    Ok(())
}


#[test]
fn settings_parse() -> TestResult {
    let settings = parse_pg_settings("100,f,160004\n".as_bytes(), MAX_CSV)?;
    assert_eq!(settings.max_connections, MAX_CONNECTIONS);
    assert!(!settings.in_recovery);
    assert_eq!(settings.version_num, VERSION);
    assert!(parse_pg_settings("100,t,160004\n".as_bytes(), MAX_CSV)?.in_recovery);
    Ok(())
}


#[test]
fn settings_refuse_bad_input() -> TestResult {
    for text in [
        "",
        "100,f\n",
        "100,f,1,9\n",
        "-5,f,160004\n",
        "1e3,f,160004\n",
        ",f,160004\n",
        "100,yes,160004\n",
        "100,f,+1\n",
        "100,f,160004\n100,f,160004\n",
    ] {
        assert!(parse_pg_settings(text.as_bytes(), MAX_CSV).is_err(), "{text:?}");
    }
    assert!(matches!(
        parse_pg_settings("100,f,160004\n100,f,160004\n".as_bytes(), MAX_CSV),
        Err(NtpError::TooManyRows { limit: 1 })
    ));
    assert!(matches!(parse_pg_settings("".as_bytes(), MAX_CSV), Err(NtpError::Malformed { .. })));
    Ok(())
}


#[test]
fn bounded_reads_and_utf8() -> TestResult {
    assert!(matches!(
        parse_pg_settings("100,f,160004\n".as_bytes(), SMALL_CAP),
        Err(NtpError::Oversized { limit: SMALL_CAP })
    ));
    assert!(matches!(parse_pg_connections(&INVALID_UTF8[..], MAX_CSV), Err(NtpError::NotUtf8(_))));
    assert!(matches!(parse_pg_connections(FailingReader, MAX_CSV), Err(NtpError::Read(_))));
    assert!(matches!(parse_pg_activity(FailingReader, MAX_CSV), Err(NtpError::Read(_))));
    assert!(matches!(parse_pg_replication(FailingReader, MAX_CSV), Err(NtpError::Read(_))));
    assert!(matches!(parse_pg_settings(FailingReader, MAX_CSV), Err(NtpError::Read(_))));
    Ok(())
}


#[test]
fn connections_parse_and_refuse() -> TestResult {
    assert_eq!(parse_pg_connections("7\n".as_bytes(), MAX_CSV)?.client_backends, SEVEN);
    for text in ["", "-5\n", "1e3\n", "\n", "1,2\n", "7\n8\n", "x\n"] {
        assert!(parse_pg_connections(text.as_bytes(), MAX_CSV).is_err(), "{text:?}");
    }
    Ok(())
}


#[test]
fn activity_parse_and_cap() -> TestResult {
    assert!(parse_pg_activity("".as_bytes(), MAX_CSV)?.durations_ms.is_empty());
    let pair = parse_pg_activity("8001\n5\n".as_bytes(), MAX_CSV)?;
    assert_eq!(pair.durations_ms, vec![SLOW_ROW_MS, FAST_ROW_MS]);
    assert!(!pair.at_least);
    let below = parse_pg_activity(rows_of(ROW_MS, ACTIVITY_CAP - 1).as_bytes(), MAX_CSV)?;
    assert!(!below.at_least);
    let full = parse_pg_activity(rows_of(ROW_MS, ACTIVITY_CAP).as_bytes(), MAX_CSV)?;
    assert!(full.at_least);
    assert_eq!(full.durations_ms.len(), ACTIVITY_CAP);
    assert!(matches!(
        parse_pg_activity(rows_of(ROW_MS, ACTIVITY_CAP + 1).as_bytes(), MAX_CSV),
        Err(NtpError::TooManyRows { limit: ACTIVITY_CAP })
    ));
    for text in ["-5\n", "1e3\n", "\n", "1,2\n", "5\n+3\n"] {
        assert!(parse_pg_activity(text.as_bytes(), MAX_CSV).is_err(), "{text:?}");
    }
    Ok(())
}


#[test]
fn replication_parse() -> TestResult {
    let parsed = parse_pg_replication("walreceiver,streaming,1500\nstandby2,catchup,\n".as_bytes(), MAX_CSV)?;
    assert_eq!(parsed.replicas.len(), TWO_REPLICAS);
    let first = parsed.replicas.first().ok_or("first")?;
    assert_eq!(first.application_name.as_deref(), Some("walreceiver"));
    assert_eq!(first.state, Some(ReplicaState::Streaming));
    assert_eq!(first.replay_lag_ms, Some(LAG_MS));
    let second = parsed.replicas.get(1).ok_or("second")?;
    assert_eq!(second.state, Some(ReplicaState::Catchup));
    assert_eq!(second.replay_lag_ms, None);
    assert_eq!((parsed.rejected_names, parsed.unknown_values), (0, 0));
    assert!(parse_pg_replication("".as_bytes(), MAX_CSV)?.replicas.is_empty());
    for (text, state) in [
        ("a,startup,\n", ReplicaState::Startup),
        ("a,backup,\n", ReplicaState::Backup),
        ("a,stopping,\n", ReplicaState::Stopping),
    ] {
        let row = parse_pg_replication(text.as_bytes(), MAX_CSV)?;
        assert_eq!(row.replicas.first().and_then(|item| item.state), Some(state));
    }
    Ok(())
}


#[test]
fn replication_names_and_states_are_allowlisted() -> TestResult {
    let long = "a".repeat(LONG_NAME_CHARS);
    let edge = "a".repeat(NAME_CHARS);
    let text = format!("a\u{202e}b,streaming,\na b,streaming,\n-x,streaming,\n{long},streaming,\n,streaming,\n{edge},streaming,\nok,weird,\n");
    let parsed = parse_pg_replication(text.as_bytes(), MAX_CSV)?;
    let names: Vec<Option<&str>> = parsed.replicas.iter().map(|item| item.application_name.as_deref()).collect();
    assert_eq!(names, vec![None, None, None, None, None, Some(edge.as_str()), Some("ok")]);
    assert_eq!(parsed.rejected_names, REJECTED_NAMES);
    assert_eq!(parsed.unknown_values, 1);
    assert_eq!(parsed.replicas.last().and_then(|item| item.state), None);
    Ok(())
}


#[test]
fn replication_refuses_bad_input() -> TestResult {
    for text in [
        "a,streaming\n",
        "a,streaming,-5\n",
        "a,streaming,1e3\n",
        "a,streaming,1,2\n",
        "a,streaming,x\n",
    ] {
        assert!(parse_pg_replication(text.as_bytes(), MAX_CSV).is_err(), "{text:?}");
    }
    assert!(matches!(
        parse_pg_replication(rows_of("a,streaming,", REPLICATION_CAP + 1).as_bytes(), MAX_CSV),
        Err(NtpError::TooManyRows { limit: REPLICATION_CAP })
    ));
    assert!(parse_pg_replication(rows_of("a,streaming,", REPLICATION_CAP).as_bytes(), MAX_CSV).is_ok());
    Ok(())
}


#[test]
fn error_text_never_holds_input() -> TestResult {
    let error = parse_pg_settings("100,f,secretvalue\n".as_bytes(), MAX_CSV)
        .err()
        .map(|failure| format!("{failure} {failure:?}"));
    assert!(error.is_some_and(|text| !text.contains("secretvalue")));
    Ok(())
}
