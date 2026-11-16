use crate::suite::common::TestResult;
use app_health::db::{assess_db, db_measures, load_db_expectations, max_lag, slow_count, streaming_count, unknown_lags};
use app_health::error::NtpError;
use app_health::model::{DbExpectation, DbHealth, DbRole, PgActivity, PgConnections, PgReplica, PgReplication, PgSettings, ReplicaState};


const MAX_CONNECTIONS: u32 = 100;


const RATIO: f64 = 0.5;


const AT_RATIO: u32 = 50;


const OVER_RATIO: u32 = 51;


const SLOW_MS: u64 = 1000;


const LAG_BOUND: u64 = 5000;


const LAG_OVER: u64 = 5001;


const MAX_DATABASES: usize = 512;


const HUGE_VALUE: usize = 10_000_000;


const VERSION: u32 = 160_004;


const TWO: usize = 2;


const NAME_LIMIT: usize = 255;


const TWO_MS: u64 = 2;


const FIVE: usize = 5;


const TWO_REPLICAS: u32 = 2;


const TWO_F: f64 = 2.0;


const ONE_F: f64 = 1.0;


fn expectation(role: DbRole, min_replicas: u32) -> DbExpectation {
    DbExpectation {
        name: "main".to_string(),
        role,
        max_connections_ratio: RATIO,
        slow_query_ms: SLOW_MS,
        max_replay_lag_ms: LAG_BOUND,
        min_replicas,
    }
}


fn settings(in_recovery: bool) -> PgSettings {
    PgSettings {
        max_connections: MAX_CONNECTIONS,
        in_recovery,
        version_num: VERSION,
    }
}


fn connections(client_backends: u32) -> PgConnections {
    PgConnections { client_backends }
}


fn activity(durations_ms: &[u64]) -> PgActivity {
    PgActivity {
        durations_ms: durations_ms.to_vec(),
        at_least: false,
    }
}


fn replica(state: Option<ReplicaState>, replay_lag_ms: Option<u64>) -> PgReplica {
    PgReplica {
        application_name: None,
        state,
        replay_lag_ms,
    }
}


fn replication(replicas: Vec<PgReplica>) -> PgReplication {
    PgReplication {
        replicas,
        rejected_names: 0,
        unknown_values: 0,
    }
}


fn streaming(lag: Option<u64>) -> PgReplica {
    replica(Some(ReplicaState::Streaming), lag)
}


fn verdict(expected: &DbExpectation, settings_in: &PgSettings, backends: u32, durations: &[u64], replicas: Vec<PgReplica>) -> DbHealth {
    assess_db(
        expected,
        Some(settings_in),
        Some(&connections(backends)),
        Some(&activity(durations)),
        Some(&replication(replicas)),
    )
}


#[test]
fn healthy_at_every_boundary() -> TestResult {
    let expected = expectation(DbRole::Primary, 1);
    let result = verdict(&expected, &settings(false), AT_RATIO, &[SLOW_MS], vec![streaming(Some(LAG_BOUND))]);
    assert_eq!(result, DbHealth::Healthy);
    Ok(())
}


#[test]
fn each_step_wins_over_the_one_below() -> TestResult {
    let expected = expectation(DbRole::Primary, 1);
    let lagging = || vec![streaming(Some(LAG_OVER))];
    let everything_bad =
        |in_recovery: bool, replicas: Vec<PgReplica>| verdict(&expected, &settings(in_recovery), OVER_RATIO, &[SLOW_MS + 1], replicas);
    assert_eq!(everything_bad(true, vec![]), DbHealth::WrongRole);
    assert_eq!(everything_bad(false, vec![]), DbHealth::ReplicaMissing);
    assert_eq!(everything_bad(false, lagging()), DbHealth::ReplicationLag { lag_ms: LAG_OVER });
    assert_eq!(
        verdict(&expected, &settings(false), OVER_RATIO, &[SLOW_MS + 1], vec![streaming(None)]),
        DbHealth::Saturated { connections: OVER_RATIO }
    );
    assert_eq!(
        verdict(&expected, &settings(false), AT_RATIO, &[SLOW_MS + 1, SLOW_MS, 1], vec![streaming(None)]),
        DbHealth::SlowQueries { count: 1 }
    );
    Ok(())
}


#[test]
fn blind_spot_for_any_missing_input() -> TestResult {
    let expected = expectation(DbRole::Unconstrained, 0);
    let known_settings = settings(false);
    let known_connections = connections(1);
    let known_activity = activity(&[]);
    let known_replication = replication(vec![]);
    assert_eq!(
        assess_db(
            &expected,
            Some(&known_settings),
            Some(&known_connections),
            Some(&known_activity),
            Some(&known_replication)
        ),
        DbHealth::Healthy
    );
    assert_eq!(
        assess_db(&expected, None, Some(&known_connections), Some(&known_activity), Some(&known_replication)),
        DbHealth::BlindSpot
    );
    assert_eq!(
        assess_db(&expected, Some(&known_settings), None, Some(&known_activity), Some(&known_replication)),
        DbHealth::BlindSpot
    );
    assert_eq!(
        assess_db(&expected, Some(&known_settings), Some(&known_connections), None, Some(&known_replication)),
        DbHealth::BlindSpot
    );
    assert_eq!(
        assess_db(&expected, Some(&known_settings), Some(&known_connections), Some(&known_activity), None),
        DbHealth::BlindSpot
    );
    Ok(())
}


#[test]
fn role_rules() -> TestResult {
    let primary = expectation(DbRole::Primary, 0);
    let replica_role = expectation(DbRole::Replica, 0);
    let any = expectation(DbRole::Unconstrained, 0);
    assert_eq!(verdict(&primary, &settings(true), 1, &[], vec![]), DbHealth::WrongRole);
    assert_eq!(verdict(&primary, &settings(false), 1, &[], vec![]), DbHealth::Healthy);
    assert_eq!(verdict(&replica_role, &settings(false), 1, &[], vec![]), DbHealth::WrongRole);
    assert_eq!(verdict(&replica_role, &settings(true), 1, &[], vec![]), DbHealth::Healthy);
    assert_eq!(verdict(&any, &settings(true), 1, &[], vec![]), DbHealth::Healthy);
    assert_eq!(verdict(&any, &settings(false), 1, &[], vec![]), DbHealth::Healthy);
    Ok(())
}


#[test]
fn replica_counting_and_unknown_lag() -> TestResult {
    let expected = expectation(DbRole::Primary, TWO_REPLICAS);
    let only_one = vec![streaming(None), replica(Some(ReplicaState::Catchup), Some(0))];
    assert_eq!(verdict(&expected, &settings(false), 1, &[], only_one), DbHealth::ReplicaMissing);
    let two = vec![streaming(None), streaming(Some(0))];
    assert_eq!(verdict(&expected, &settings(false), 1, &[], two), DbHealth::Healthy);
    let unknown = replication(vec![
        replica(Some(ReplicaState::Catchup), None),
        replica(None, None),
        streaming(None),
        streaming(Some(LAG_BOUND)),
    ]);
    assert_eq!(unknown_lags(&unknown), TWO);
    assert_eq!(streaming_count(&unknown), TWO);
    assert_eq!(max_lag(&unknown), Some(LAG_BOUND));
    assert_eq!(max_lag(&replication(vec![replica(Some(ReplicaState::Catchup), None)])), None);
    assert_eq!(max_lag(&replication(vec![streaming(None)])), Some(0));
    let lagging_catchup = vec![replica(Some(ReplicaState::Catchup), Some(LAG_OVER))];
    assert_eq!(
        verdict(&expectation(DbRole::Primary, 0), &settings(false), 1, &[], lagging_catchup),
        DbHealth::ReplicationLag { lag_ms: LAG_OVER }
    );
    let silent_catchup = vec![replica(Some(ReplicaState::Catchup), None)];
    assert_eq!(
        verdict(&expectation(DbRole::Primary, 0), &settings(false), 1, &[], silent_catchup),
        DbHealth::Healthy
    );
    Ok(())
}


#[test]
fn slow_count_is_strict() -> TestResult {
    let expected = expectation(DbRole::Unconstrained, 0);
    assert_eq!(slow_count(&expected, &activity(&[SLOW_MS, SLOW_MS + 1, SLOW_MS + TWO_MS])), TWO);
    Ok(())
}


#[test]
fn measures_skip_missing_values() -> TestResult {
    let expected = expectation(DbRole::Unconstrained, 0);
    assert!(db_measures(&expected, None, None, None).is_empty());
    let all = db_measures(
        &expected,
        Some(&connections(AT_RATIO)),
        Some(&activity(&[SLOW_MS + 1, 1])),
        Some(&replication(vec![streaming(Some(LAG_BOUND)), replica(None, None)])),
    );
    let named: Vec<(&str, f64)> = all.iter().map(|item| (item.name, item.value)).collect();
    assert_eq!(
        named,
        vec![
            ("db.connections", f64::from(AT_RATIO)),
            ("db.active_queries", TWO_F),
            ("db.slow_queries", ONE_F),
            ("db.replay_lag_max", LAG_BOUND as f64),
            ("db.replay_lag_unknown", ONE_F),
        ]
    );
    let no_lag = db_measures(&expected, None, None, Some(&replication(vec![replica(None, None)])));
    assert_eq!(no_lag.iter().map(|item| item.name).collect::<Vec<_>>(), vec!["db.replay_lag_unknown"]);
    Ok(())
}


fn yaml(fields: &str) -> String {
    format!("databases:\n  - name: main\n    role: primary\n    max_connections_ratio: 0.8\n    slow_query_ms: 1000\n    max_replay_lag_ms: 5000\n    min_replicas: 1\n{fields}")
}


#[test]
fn expectations_load() -> TestResult {
    let loaded = load_db_expectations(&yaml(""), "db.yaml")?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.first().map(|item| item.role), Some(DbRole::Primary));
    let both = "databases:\n  - {name: a, role: replica, max_connections_ratio: 1, slow_query_ms: 100, max_replay_lag_ms: 0, min_replicas: 0}\n  - {name: b, role: any, max_connections_ratio: 0.1, slow_query_ms: 86400000, max_replay_lag_ms: 86400000, min_replicas: 16}\n";
    assert_eq!(load_db_expectations(both, "db.yaml")?.len(), TWO);
    Ok(())
}


fn one(field: &str, value: &str) -> String {
    let defaults = [
        ("name", "main"),
        ("role", "any"),
        ("max_connections_ratio", "0.5"),
        ("slow_query_ms", "1000"),
        ("max_replay_lag_ms", "5000"),
        ("min_replicas", "0"),
    ];
    let fields: Vec<String> = defaults
        .iter()
        .map(|(key, default)| format!("    {key}: {}", if *key == field { value } else { default }))
        .collect();
    format!("databases:\n  -\n{}\n", fields.join("\n"))
}


#[test]
fn expectations_refuse_out_of_range() -> TestResult {
    let cases = [
        ("name", "-x"),
        ("name", "a b"),
        ("name", ""),
        ("max_connections_ratio", "0"),
        ("max_connections_ratio", "1.01"),
        ("max_connections_ratio", ".nan"),
        ("max_connections_ratio", "-0.5"),
        ("slow_query_ms", "99"),
        ("slow_query_ms", "86400001"),
        ("max_replay_lag_ms", "86400001"),
        ("min_replicas", "17"),
        ("role", "boss"),
    ];
    for (field, value) in cases {
        assert!(load_db_expectations(&one(field, value), "db.yaml").is_err(), "{field}={value}");
    }
    assert!(load_db_expectations(&one("name", "ok-name"), "db.yaml").is_ok());
    assert!(load_db_expectations(&one("name", &"a".repeat(NAME_LIMIT)), "db.yaml").is_ok());
    assert!(load_db_expectations(&one("name", &"a".repeat(NAME_LIMIT + 1)), "db.yaml").is_err());
    Ok(())
}


#[test]
fn expectations_refuse_unknown_fields_and_sizes() -> TestResult {
    assert!(load_db_expectations(&yaml("    extra: 1\n"), "db.yaml").is_err());
    assert!(load_db_expectations("databases: []\nextra: 1\n", "db.yaml").is_err());
    let padding = " ".repeat(HUGE_VALUE / FIVE);
    assert!(matches!(
        load_db_expectations(&format!("databases: []\n{padding}\n"), "db.yaml"),
        Err(NtpError::Oversized { .. })
    ));
    let entry = "  - {name: a, role: any, max_connections_ratio: 0.5, slow_query_ms: 1000, max_replay_lag_ms: 0, min_replicas: 0}\n";
    let many = format!("databases:\n{}", entry.repeat(MAX_DATABASES + 1));
    assert!(matches!(
        load_db_expectations(&many, "db.yaml"),
        Err(NtpError::OutOfRange { field: "databases" })
    ));
    let exact = format!("databases:\n{}", entry.repeat(MAX_DATABASES));
    assert_eq!(load_db_expectations(&exact, "db.yaml").map(|items| items.len()).ok(), Some(MAX_DATABASES));
    Ok(())
}
