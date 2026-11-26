#![cfg(unix)]


#[path = "common/payloads.rs"]
mod payloads;
#[path = "common/site.rs"]
mod site;
#[path = "common/stand_in.rs"]
mod stand_in;
#[path = "common/types.rs"]
mod types;


use cmdb::model::{DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use core_config::error::ConfigError;
use core_pg::error::PgError;
use core_pg::settings::load_settings as load_pg_settings;
use payloads::{ADMIN, AUDITOR, RESOURCES};
use pg_fake::fake::Reply;
use serde_json::error::Category;
use siem_ingest::error::{InsertClass, InsertError};
use site::{applying, pg_with, write_site, Site};
use stand_in::{reply, spawn_stand_in};
use std::error::Error;
use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use tempfile::tempdir;
use types::TestResult;
use virt_inventory::cmdb_sync::SyncReport;
use virt_inventory::error::{FetchError, InventoryError, ParseError, ReadOnlyError, RoundError, ServiceError, SyncError};
use virt_inventory::model::{Context, RoundReport, Skipped};
use virt_inventory::serve::{exit_code, log_round};
use virt_inventory::service::{
    limits_of, load_service_settings, production_round, round_entry, round_parameters, round_reason, run_round, validate_service, ServiceSettings,
};
use virt_inventory::settings::load_settings;


const THREE_ROUNDS: usize = 3;


const OK: u16 = 200;


const MIN_INTERVAL: u64 = 60;


const MAX_INTERVAL: u64 = 86_400;


const SMALL_ASSETS: usize = 5;


const SMALL_ROWS: usize = 7;


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIVE: usize = 5;


const SIX: usize = 6;


const SEVEN: usize = 7;


const DENIED: u16 = 401;


const MARKER: &str = "SECRET-MARKER";


fn settings_of(interval_seconds: u64, max_assets: usize, max_child_rows: usize) -> ServiceSettings {
    ServiceSettings {
        fetch_settings: "f".into(),
        pg_settings: "p".into(),
        audit_file: "a".into(),
        interval_seconds,
        max_assets,
        max_child_rows,
    }
}


fn context_of(site: &Site) -> Result<Context, Box<dyn Error>> {
    let settings = load_service_settings(&site.settings_file)?;
    Ok(Context {
        fetch: load_settings(&settings.fetch_settings)?,
        pg: load_pg_settings(&settings.pg_settings)?,
        limits: limits_of(&settings),
    })
}


fn report_of(skipped: Skipped) -> RoundReport {
    RoundReport {
        sync: SyncReport::default(),
        skipped,
    }
}


fn reason_of(error: FetchError) -> String {
    round_reason(&RoundError::Fetch(error))
}


fn parse_reason_of(cause: ParseError) -> String {
    reason_of(FetchError::Resources(cause))
}


fn config_error() -> ConfigError {
    ConfigError::TooLarge {
        file: MARKER.to_owned(),
        max: 1,
    }
}


#[test]
fn the_service_settings_bounds_are_checked() -> TestResult {
    validate_service(&settings_of(MIN_INTERVAL, 1, 1))?;
    validate_service(&settings_of(MAX_INTERVAL, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS))?;
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL - 1, 1, 1)),
        Err(ServiceError::Interval { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MAX_INTERVAL + 1, 1, 1)),
        Err(ServiceError::Interval { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 0, 1)),
        Err(ServiceError::MaxAssets { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, DEFAULT_MAX_ASSETS + 1, 1)),
        Err(ServiceError::MaxAssets { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 1, 0)),
        Err(ServiceError::MaxChildRows { .. })
    ));
    assert!(matches!(
        validate_service(&settings_of(MIN_INTERVAL, 1, DEFAULT_MAX_CHILD_ROWS + 1)),
        Err(ServiceError::MaxChildRows { .. })
    ));
    Ok(())
}


#[test]
fn the_lab_caps_are_settings_with_the_store_defaults_otherwise() -> TestResult {
    let dir = tempdir()?;
    let plain = write_site(dir.path(), 1, "", 1, "", "")?;
    assert!(!plain.audit_file.exists());
    let defaults = load_service_settings(&plain.settings_file)?;
    assert_eq!(
        (defaults.max_assets, defaults.max_child_rows),
        (DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS)
    );
    let capped = write_site(
        dir.path(),
        1,
        "",
        1,
        "",
        &format!("max_assets: {SMALL_ASSETS}\nmax_child_rows: {SMALL_ROWS}\n"),
    )?;
    let settings = load_service_settings(&capped.settings_file)?;
    let limits = limits_of(&settings);
    assert_eq!((limits.max_assets, limits.max_child_rows), (SMALL_ASSETS, SMALL_ROWS));
    cmdb::store::check_limits(&limits)?;
    let largest = settings_of(MAX_INTERVAL, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS);
    cmdb::store::check_limits(&limits_of(&largest))?;
    let unknown = write_site(dir.path(), 1, "", 1, "", "tenant: other\n")?;
    assert!(load_service_settings(&unknown.settings_file).is_err());
    let bad = write_site(dir.path(), 1, "", 1, "", "max_assets: 0\n")?;
    assert!(load_service_settings(&bad.settings_file).is_err());
    Ok(())
}


#[test]
fn a_round_record_is_under_the_all_tenant_and_names_the_cluster() -> TestResult {
    let good = round_entry("pve-1", &Ok(report_of(Skipped::default())));
    assert_eq!(
        (good.tenant.as_str(), good.target.as_str(), good.module.as_str()),
        ("all", "pve-1", "virt-inventory")
    );
    assert!(matches!(good.outcome, core_audit::model::Outcome::Success));
    assert_eq!(good.parameters.get("created").map(String::as_str), Some("0"));
    let bad = round_entry("pve-1", &Err(RoundError::Fetch(FetchError::Url)));
    assert!(matches!(bad.outcome, core_audit::model::Outcome::Failure));
    assert_eq!(
        round_parameters(&Err(RoundError::Fetch(FetchError::Url)))
            .get("round_error")
            .map(String::as_str),
        Some("fetch_settings")
    );
    Ok(())
}


#[test]
fn the_parse_level_skips_are_counted_in_the_audit_parameters() -> TestResult {
    let skipped = Skipped {
        unparsable: 1,
        bad_field: TWO,
        duplicate: THREE,
        other_type: FOUR,
        key_lost: FIVE,
        name_dropped: SIX,
        field_dropped: SEVEN,
        refused_keys: Vec::new(),
    };
    let parameters = round_parameters(&Ok(report_of(skipped)));
    let expected = [
        ("skipped_unparsable", "1"),
        ("skipped_bad_field", "2"),
        ("skipped_duplicate", "3"),
        ("skipped_other_type", "4"),
        ("skipped_key_lost", "5"),
        ("name_dropped", "6"),
        ("field_dropped", "7"),
    ];
    expected
        .iter()
        .for_each(|(name, count)| assert_eq!(parameters.get(*name).map(String::as_str), Some(*count), "{name}"));
    Ok(())
}


#[test]
fn every_failure_has_a_fixed_audit_category_that_carries_no_text_of_the_cause() -> TestResult {
    assert_eq!(parse_reason_of(ParseError::Read(io::Error::other(MARKER))), "resources_read");
    assert_eq!(parse_reason_of(ParseError::TooLarge { max: 1 }), "resources_too_large");
    let malformed = ParseError::Malformed {
        category: Category::Syntax,
        line: 1,
        column: 1,
    };
    assert_eq!(parse_reason_of(malformed), "resources_malformed");
    assert_eq!(parse_reason_of(ParseError::TooManyItems { count: TWO, max: 1 }), "resources_TooManyItems");
    assert_eq!(
        parse_reason_of(ParseError::TooManyPrivileges { count: TWO, max: 1 }),
        "resources_TooManyPrivileges"
    );
    assert_eq!(
        parse_reason_of(ParseError::TooManyGrants { count: TWO, max: 1 }),
        "resources_TooManyGrants"
    );
    assert_eq!(parse_reason_of(ParseError::BadPermission), "resources_bad_permission");
    assert_eq!(
        reason_of(FetchError::Permissions(ParseError::TooManyItems { count: TWO, max: 1 })),
        "permissions_TooManyItems"
    );
    let writable = ReadOnlyError::HasWriteRights {
        privileges: vec![MARKER.to_owned()],
        omitted: 0,
    };
    assert_eq!(reason_of(FetchError::WritableCredential(writable)), "not_read_only");
    assert_eq!(reason_of(FetchError::WritableCredential(ReadOnlyError::NoRights)), "no_rights");
    assert_eq!(reason_of(FetchError::Certificate), "certificate");
    assert_eq!(reason_of(FetchError::Transport(InsertClass::Unavailable)), "transport");
    assert_eq!(reason_of(FetchError::Status(DENIED)), "status");
    assert_eq!(reason_of(FetchError::CaFile(config_error())), "ca_file");
    let secret_file = PgError::SecretMode { file: MARKER.to_owned() };
    assert_eq!(reason_of(FetchError::TokenFile(secret_file)), "token");
    assert_eq!(reason_of(FetchError::TokenShape), "token");
    assert_eq!(reason_of(FetchError::Body(io::Error::other(MARKER))), "body");
    assert_eq!(reason_of(FetchError::TooLarge { max: 1 }), "body");
    assert_eq!(reason_of(FetchError::Config(config_error())), "fetch_settings");
    assert_eq!(reason_of(FetchError::Url), "fetch_settings");
    assert_eq!(reason_of(FetchError::Timeout), "fetch_settings");
    assert_eq!(reason_of(FetchError::MaxBytes), "fetch_settings");
    assert_eq!(reason_of(FetchError::Scope(InventoryError::ScopeMismatch)), "fetch_settings");
    assert_eq!(reason_of(FetchError::Agent(InsertError::CaTooLarge)), "fetch_settings");
    let unreachable = PgError::ConnectTimeout { seconds: 1 };
    assert_eq!(round_reason(&RoundError::Pg(unreachable)), "store_unreachable");
    assert_eq!(round_reason(&RoundError::Sync(SyncError::BadIdentity { field: "x" })), "sync_failed");
    Ok(())
}


#[test]
fn the_exit_code_follows_the_result() -> TestResult {
    assert_eq!(format!("{:?}", exit_code(&Ok(()))), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(format!("{:?}", exit_code(&Err("x".into()))), format!("{:?}", ExitCode::FAILURE));
    log_round(&Ok(report_of(Skipped::default())));
    log_round(&Err(RoundError::Fetch(FetchError::Url)));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_fetches_then_syncs_and_a_write_capable_token_syncs_nothing() -> TestResult {
    let dir = tempdir()?;
    let (mut fake, pg_ca) = pg_with(applying()).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES), reply(OK, ADMIN)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let context = context_of(&site)?;
    let report = run_round(&context).await?;
    assert!(report.sync.created > 0, "{report:?}");
    let refused = production_round(&context).await.err().ok_or("expected a refusal")?;
    assert!(matches!(refused, RoundError::Fetch(FetchError::WritableCredential(_))), "{refused}");
    let applied = std::iter::from_fn(|| fake.statements.try_recv().ok())
        .filter(|text| text.starts_with(cmdb::store::APPLY_SQL))
        .count();
    assert_eq!(applied, 1);
    let seen = stand_in.seen.join().map_err(|_| "stand-in panicked")??;
    assert_eq!(seen.len(), THREE_ROUNDS);
    assert!(seen.iter().all(|request| request.request_line.starts_with("GET /api2/json/")));
    assert!(seen.iter().all(|request| request.authorization.is_some()));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_or_failing_store_is_a_named_round_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, pg_ca) = pg_with(Arc::new(|_| Reply::Error("XX000"))).await?;
    let stand_in = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let site = write_site(dir.path(), fake.port, &pg_ca, stand_in.port, &stand_in.ca_pem, "")?;
    let context = context_of(&site)?;
    let failed = run_round(&context).await.err().ok_or("expected a store error")?;
    assert!(matches!(failed, RoundError::Sync(_)), "{failed}");
    let held = std::net::TcpListener::bind("127.0.0.1:0")?;
    let again = spawn_stand_in(vec![reply(OK, AUDITOR), reply(OK, RESOURCES)])?;
    let second = tempdir()?;
    let closed = write_site(second.path(), held.local_addr()?.port(), &pg_ca, again.port, &again.ca_pem, "")?;
    let offline = context_of(&closed)?;
    let error = run_round(&offline).await.err().ok_or("expected a connection error")?;
    assert!(matches!(error, RoundError::Pg(_)), "{error}");
    Ok(())
}
