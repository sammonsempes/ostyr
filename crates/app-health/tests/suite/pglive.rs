use crate::suite::common::TestResult;
use app_health::db::{assess_db, load_db_expectations};
use app_health::model::{DbHealth, ReplicaState};
use app_health::pg::{parse_pg_activity, parse_pg_connections, parse_pg_replication, parse_pg_settings};


const DATABASES: &str = include_str!("../fixtures/databases.yaml");


const MAX_CSV: u64 = 65_536;


const FILE_COUNT: usize = 4;


const LAB_VERSION: u32 = 160_015;


const LAB_LAG_MS: u64 = 26_334;


const BUSY_CONNECTIONS: u32 = 3;


const BUSY_SESSIONS: usize = 2;


const IDLE_PRIMARY: [&str; FILE_COUNT] = [
    include_str!("../fixtures/lab-pg-primary-idle-settings.csv"),
    include_str!("../fixtures/lab-pg-primary-idle-connections.csv"),
    include_str!("../fixtures/lab-pg-primary-idle-activity.csv"),
    include_str!("../fixtures/lab-pg-primary-idle-replication.csv"),
];


const BUSY_PRIMARY: [&str; FILE_COUNT] = [
    include_str!("../fixtures/lab-pg-primary-busy-settings.csv"),
    include_str!("../fixtures/lab-pg-primary-busy-connections.csv"),
    include_str!("../fixtures/lab-pg-primary-busy-activity.csv"),
    include_str!("../fixtures/lab-pg-primary-busy-replication.csv"),
];


const STOPPED_REPLICA: [&str; FILE_COUNT] = [
    include_str!("../fixtures/lab-pg-replica-stopped-settings.csv"),
    include_str!("../fixtures/lab-pg-replica-stopped-connections.csv"),
    include_str!("../fixtures/lab-pg-replica-stopped-activity.csv"),
    include_str!("../fixtures/lab-pg-replica-stopped-replication.csv"),
];


const LAGGING_REPLICA: [&str; FILE_COUNT] = [
    include_str!("../fixtures/lab-pg-replica-lagging-settings.csv"),
    include_str!("../fixtures/lab-pg-replica-lagging-connections.csv"),
    include_str!("../fixtures/lab-pg-replica-lagging-activity.csv"),
    include_str!("../fixtures/lab-pg-replica-lagging-replication.csv"),
];


const IDLE_REPLICA: [&str; FILE_COUNT] = [
    include_str!("../fixtures/lab-pg-replica-idle-settings.csv"),
    include_str!("../fixtures/lab-pg-replica-idle-connections.csv"),
    include_str!("../fixtures/lab-pg-replica-idle-activity.csv"),
    include_str!("../fixtures/lab-pg-replica-idle-replication.csv"),
];


fn live_verdict(database: &str, files: [&str; FILE_COUNT]) -> Result<DbHealth, Box<dyn std::error::Error>> {
    let expectations = load_db_expectations(DATABASES, "databases.yaml")?;
    let expectation = expectations.iter().find(|item| item.name == database).ok_or("missing expectation")?;
    let [settings, connections, activity, replication] = files;
    Ok(assess_db(
        expectation,
        Some(&parse_pg_settings(settings.as_bytes(), MAX_CSV)?),
        Some(&parse_pg_connections(connections.as_bytes(), MAX_CSV)?),
        Some(&parse_pg_activity(activity.as_bytes(), MAX_CSV)?),
        Some(&parse_pg_replication(replication.as_bytes(), MAX_CSV)?),
    ))
}


#[test]
fn lab_captures_give_each_verdict() -> TestResult {
    assert_eq!(live_verdict("primary", IDLE_PRIMARY)?, DbHealth::Healthy);
    assert_eq!(live_verdict("primary", BUSY_PRIMARY)?, DbHealth::SlowQueries { count: BUSY_SESSIONS });
    assert_eq!(live_verdict("primary", STOPPED_REPLICA)?, DbHealth::ReplicaMissing);
    assert_eq!(live_verdict("primary", LAGGING_REPLICA)?, DbHealth::ReplicationLag { lag_ms: LAB_LAG_MS });
    assert_eq!(live_verdict("replica", IDLE_REPLICA)?, DbHealth::Healthy);
    assert_eq!(live_verdict("primary", IDLE_REPLICA)?, DbHealth::WrongRole);
    Ok(())
}


#[test]
fn lab_forms_of_null_boolean_and_state() -> TestResult {
    let [settings, connections, _, replication] = IDLE_PRIMARY;
    let parsed_settings = parse_pg_settings(settings.as_bytes(), MAX_CSV)?;
    assert!(!parsed_settings.in_recovery);
    assert_eq!(parsed_settings.version_num, LAB_VERSION);
    assert_eq!(parse_pg_connections(connections.as_bytes(), MAX_CSV)?.client_backends, 1);
    let streaming = parse_pg_replication(replication.as_bytes(), MAX_CSV)?;
    let row = streaming.replicas.first().ok_or("row")?;
    assert_eq!((row.state, row.replay_lag_ms), (Some(ReplicaState::Streaming), None));
    assert_eq!(row.application_name.as_deref(), Some("ostyr_replica"));
    let [replica_settings, _, _, _] = IDLE_REPLICA;
    assert!(parse_pg_settings(replica_settings.as_bytes(), MAX_CSV)?.in_recovery);
    let [_, busy_connections, _, _] = BUSY_PRIMARY;
    assert_eq!(
        parse_pg_connections(busy_connections.as_bytes(), MAX_CSV)?.client_backends,
        BUSY_CONNECTIONS
    );
    Ok(())
}
