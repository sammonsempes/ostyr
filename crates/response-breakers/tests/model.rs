#[path = "common/types.rs"]
mod types;


use core_config::parse::parse_document;
use ipnet::IpNet;
use response_breakers::cli::parse_action;
use response_breakers::config::{apply_overrides, config_state, limits_for, BreakerConfig, LimitOverrides, Limits};
use response_breakers::model::{limit_label, ActionKind, LimitName, Reason, Verdict, ALL_LIMITS};
use response_breakers::store::{open_store, persist, prune, sync_path, Event, Override, StoreState, DAY_SECONDS};
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


const NOW: i64 = 1_800_000_000;


const ONE_HOUR: i64 = 3600;


const REPLACED: u64 = 9;


const RMM_CURRENT: u64 = 21;


const RMM_MAX: u64 = 20;


const HOURLY_ISOLATIONS: u64 = 5;


const DAILY_ISOLATIONS: u64 = 20;


const HOURLY_DISABLINGS: u64 = 3;


const HOURLY_BLOCKS: u64 = 50;


const BLOCK_DAYS: u64 = 7;


const ISOLATED_PERCENT: u64 = 2;


const RANGE_COUNT: usize = 8;


const RAISED_BLOCKS: u64 = 60;


const FLEET: u64 = 50;


#[test]
fn limit_names_round_trip_through_their_labels() -> TestResult {
    ALL_LIMITS.iter().for_each(|limit| {
        assert_eq!(limit_label(*limit).parse::<LimitName>(), Ok(*limit));
        assert_eq!(limit.to_string(), limit_label(*limit));
    });
    assert_eq!("nothing".parse::<LimitName>(), Err("nothing".to_owned()));
    let json = serde_json::to_string(&LimitName::BlocksPerHour)?;
    assert_eq!(json, "\"blocks_per_hour\"");
    Ok(())
}


#[test]
fn reasons_and_verdicts_read_well() -> TestResult {
    let reached = Reason::LimitReached {
        limit: LimitName::RmmMachines,
        current: RMM_CURRENT,
        max: RMM_MAX,
    };
    assert_eq!(reached.to_string(), "limit rmm_machines reached: 21 of 20");
    assert!(Reason::ProtectedTag { tag: "critical".to_owned() }.to_string().contains("`critical`"));
    assert!(Reason::ReservedRange {
        range: "10.0.0.0/8".to_owned()
    }
    .to_string()
    .contains("10.0.0.0/8"));
    assert!(Reason::RecordFailed { message: "disk".to_owned() }.to_string().ends_with("disk"));
    assert_eq!(Verdict::Allowed { overridden: Vec::new() }.to_string(), "allowed");
    assert_eq!(
        Verdict::NeedsApproval {
            reason: reached,
            alert_on_call: true
        }
        .to_string(),
        "needs-approval alert=true reason=limit rmm_machines reached: 21 of 20"
    );
    Ok(())
}


#[test]
fn defaults_match_the_spec_table() -> TestResult {
    let limits = Limits::default();
    assert_eq!(
        (
            limits.isolations_per_hour,
            limits.isolations_per_day,
            limits.disablings_per_hour,
            limits.blocks_per_hour
        ),
        (HOURLY_ISOLATIONS, DAILY_ISOLATIONS, HOURLY_DISABLINGS, HOURLY_BLOCKS)
    );
    assert_eq!(
        (limits.block_max_days, limits.rmm_max_machines, limits.max_isolated_percent),
        (BLOCK_DAYS, RMM_MAX, ISOLATED_PERCENT)
    );
    assert_eq!(limits.protected_host_tags, ["domain-controller", "hypervisor", "critical"]);
    assert_eq!(limits.protected_account_tags, ["privileged", "break-glass", "service"]);
    assert_eq!(limits.reserved_ranges.len(), RANGE_COUNT);
    Ok(())
}


#[test]
fn a_tenant_replaces_only_the_fields_it_names() -> TestResult {
    let text = "limits:\n  blocks_per_hour: 60\ntenants:\n  acme:\n    isolations_per_hour: 9\n";
    let config: BreakerConfig = parse_document(text, "limits.yaml")?;
    let acme = limits_for(&config, "acme");
    assert_eq!((acme.isolations_per_hour, acme.blocks_per_hour), (REPLACED, RAISED_BLOCKS));
    assert_eq!(limits_for(&config, "other").isolations_per_hour, Limits::default().isolations_per_hour);
    let range: IpNet = "192.0.2.0/24".parse()?;
    let everything = LimitOverrides {
        isolations_per_hour: Some(REPLACED),
        isolations_per_day: Some(REPLACED),
        disablings_per_hour: Some(REPLACED),
        blocks_per_hour: Some(REPLACED),
        block_max_days: Some(REPLACED),
        rmm_max_machines: Some(REPLACED),
        max_isolated_percent: Some(REPLACED),
        protected_host_tags: Some(vec!["a".to_owned()]),
        protected_account_tags: Some(vec!["b".to_owned()]),
        reserved_ranges: Some(vec![range]),
    };
    let replaced = apply_overrides(&Limits::default(), &everything);
    assert_eq!(replaced.reserved_ranges, vec![range]);
    assert_eq!(replaced.protected_host_tags, ["a"]);
    assert_eq!(replaced.protected_account_tags, ["b"]);
    assert_eq!(replaced.block_max_days, REPLACED);
    assert_eq!(apply_overrides(&replaced, &LimitOverrides::default()), replaced);
    let keys: Vec<String> = config_state(&config).into_keys().collect();
    assert_eq!(keys, ["limits", "tenants.acme"]);
    Ok(())
}


#[test]
fn unknown_fields_and_bad_ranges_are_refused_with_their_path() -> TestResult {
    let unknown: Result<BreakerConfig, _> = parse_document("limits:\n  surprise: 1\n", "limits.yaml");
    assert!(unknown.is_err_and(|error| error.to_string().contains("limits.yaml:2")));
    let tenant: Result<BreakerConfig, _> = parse_document("tenants:\n  acme:\n    surprise: 1\n", "limits.yaml");
    assert!(tenant.is_err());
    let top: Result<BreakerConfig, _> = parse_document("surprise: 1\n", "limits.yaml");
    assert!(top.is_err());
    let range: Result<BreakerConfig, _> = parse_document("limits:\n  reserved_ranges: [\"10.0.0.0/99\"]\n", "limits.yaml");
    assert!(range.is_err_and(|error| error.to_string().contains("limits.reserved_ranges")));
    Ok(())
}


#[test]
fn actions_parse_from_command_words() -> TestResult {
    let isolate = parse_action(&["isolate", "acme", "host-1", "50", "1", "a,b"])?;
    assert_eq!(
        isolate.kind,
        ActionKind::IsolateEndpoint {
            fleet_size: FLEET,
            isolated_now: 1
        }
    );
    assert_eq!(isolate.target.tags, ["a", "b"]);
    assert!(parse_action(&["disable", "acme", "bob"])?.target.tags.is_empty());
    assert!(parse_action(&["block-ip", "acme", "::1", "5"]).is_ok());
    assert!(parse_action(&["block-domain", "acme", "example.org", "5"]).is_ok());
    assert!(parse_action(&["rmm", "acme", "host-1", "5", ",x"]).is_ok_and(|action| action.target.tags == ["x"]));
    assert!(parse_action(&["isolate", "acme", "host-1", "x", "1"]).is_err());
    assert!(parse_action(&["isolate", "acme", "host-1", "1", "x"]).is_err());
    assert!(parse_action(&["block-ip", "acme", "host", "5"]).is_err());
    assert!(parse_action(&["block-ip", "acme", "::1", "x"]).is_err());
    assert!(parse_action(&["block-domain", "acme", "d", "x"]).is_err());
    assert!(parse_action(&["rmm", "acme", "h", "x"]).is_err());
    assert!(parse_action(&[]).is_err());
    Ok(())
}


#[test]
fn the_store_is_written_durably_and_pruned() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("counters.json");
    let fresh = open_store(&path, sync_path)?;
    assert_eq!(*fresh.state.lock().map_err(|_| "poisoned")?, StoreState::default());
    let state = StoreState {
        events: vec![
            Event {
                at: NOW - DAY_SECONDS,
                tenant: "acme".to_owned(),
                counter: response_breakers::model::Counter::Block,
            },
            Event {
                at: NOW - ONE_HOUR,
                tenant: "acme".to_owned(),
                counter: response_breakers::model::Counter::Block,
            },
        ],
        overrides: vec![
            Override {
                tenant: "acme".to_owned(),
                limit: LimitName::BlocksPerHour,
                until: NOW,
            },
            Override {
                tenant: "acme".to_owned(),
                limit: LimitName::BlocksPerHour,
                until: NOW + 1,
            },
        ],
    };
    let kept = prune(&state, NOW);
    assert_eq!((kept.events.len(), kept.overrides.len()), (1, 1));
    persist(&path, &kept, sync_path)?;
    assert!(!path.with_extension("tmp").exists());
    let reopened = open_store(&path, sync_path)?;
    assert_eq!(*reopened.state.lock().map_err(|_| "poisoned")?, kept);
    fs::write(&path, "{\"events\":[],\"overrides\":[],\"extra\":1}")?;
    assert!(open_store(&path, sync_path).is_err());
    Ok(())
}


#[test]
fn persist_reports_each_failing_step() -> TestResult {
    let dir = tempdir()?;
    let state = StoreState::default();
    let missing = dir.path().join("nothing").join("counters.json");
    assert!(persist(&missing, &state, sync_path).is_err());
    let blocked = dir.path().join("blocked");
    fs::create_dir(&blocked)?;
    assert!(persist(&blocked, &state, sync_path).is_err());
    let plain = dir.path().join("counters.json");
    assert!(persist(&plain, &state, |_path: &Path| Err(std::io::Error::other("disk"))).is_err());
    assert!(persist(&plain, &state, |path: &Path| if path.is_dir() {
        Err(std::io::Error::other("disk"))
    } else {
        Ok(())
    })
    .is_err());
    assert!(persist(Path::new("relative-counters.json"), &state, |_path: &Path| Ok(())).is_ok());
    fs::remove_file("relative-counters.json")?;
    assert!(sync_path(&dir.path().join("absent")).is_err());
    assert!(sync_path(dir.path()).is_ok());
    Ok(())
}
