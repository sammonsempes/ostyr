#[path = "common/stub.rs"]
mod stub;
#[path = "common/types.rs"]
mod types;


use cloud_cost::load::{
    agent_for, load_table, post, BatchFailure, LoadError, LoadOutcome, Statement, MAX_REPLACE_ACCOUNTS, MAX_REPLACE_ACCOUNT_BYTES,
};
use cloud_cost::model::{CostTable, Limits};
use cloud_cost::settings::CostLoadConfig;
use cloud_cost::source::{read_export, Export};
use cloud_cost::store::ROWS_PER_BATCH;
use siem_ingest::clickhouse::MAX_CA_BYTES;
use siem_ingest::error::InsertClass;
use std::cell::Cell;
use std::error::Error;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;
use stub::{serve, stall};
use tempfile::{tempdir, TempDir};
use types::TestResult;


const HEADER: &str = "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags";


const PASSWORD: &str = "TRACEPW-5b2e8d40";


const TWICE: usize = 2;


const OK: &str = "200 OK";


const SERVER_ERROR: &str = "500 Internal Server Error";


const VERSION: u64 = 1_700_000_000_000;


const SCHEMA_REQUESTS: usize = 2;


const REQUESTS_BEFORE_INSERT: usize = 3;


const STALL_TIMEOUT_MS: u64 = 100;


const LONG_TIMEOUT_MS: u64 = 60_000;


const ONE_HOUR: Duration = Duration::from_secs(3600);


const OVER_PASSWORD: usize = 8192;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const JANUARY_ROWS: usize = 4;


const SECOND_BATCH_ROWS: usize = 1;


struct Rig {
    dir: TempDir,
    config: CostLoadConfig,
    listener: TcpListener,
}


fn rig(timeout_ms: u64) -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    fs::write(dir.path().join("password"), format!("{PASSWORD}\n"))?;
    let config = CostLoadConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_owned(),
        password_file: dir.path().join("password"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "cloud_cost_daily".to_owned(),
        timeout_ms,
        ttl_days: 1,
        tenant: "acme".to_owned(),
    };
    Ok(Rig { dir, config, listener })
}


fn export_of(lines: &[&str], tenant: &str) -> Result<Export, Box<dyn Error>> {
    let text = format!("{HEADER}\n{}\n", lines.join("\n"));
    Ok(read_export(text.as_bytes(), &Limits::default(), tenant)?)
}


fn january() -> Result<Export, Box<dyn Error>> {
    export_of(
        &["1.5,USD,acct,2026-01-05T10:00:00Z,compute,", "2.5,USD,acct,2026-01-07T10:00:00Z,compute,"],
        "acme",
    )
}


fn idle() -> Duration {
    Duration::ZERO
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined<Output>(handle: std::thread::JoinHandle<io::Result<Output>>) -> Result<Output, Box<dyn Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn body_of(request: &str) -> &str {
    request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}


#[test]
fn schema_replace_then_insert_in_order_with_the_key_in_a_header_only() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; REQUESTS_BEFORE_INSERT + 1]);
    let outcome = load_table(&rig.config, &january()?, VERSION, &idle)?;
    assert_eq!(outcome.failure, None);
    assert_eq!(outcome.batches_planned, 1);
    let seen = joined(server)?;
    let head = |index: usize| -> Result<&str, Box<dyn Error>> { Ok(seen.get(index).ok_or("missing request")?.lines().next().unwrap_or("")) };
    assert!(
        head(0)?.contains("CREATE+DATABASE") || head(0)?.contains("CREATE%20DATABASE"),
        "{}",
        head(0)?
    );
    assert!(head(1)?.contains("CREATE"));
    let delete = head(SCHEMA_REQUESTS)?;
    assert!(delete.contains("DELETE"), "{delete}");
    assert!(delete.contains("param_tenant=acme"), "{delete}");
    assert!(delete.contains("param_first=2026-01-05"), "{delete}");
    assert!(delete.contains("param_last=2026-01-07"), "{delete}");
    assert!(delete.contains("account+IN") || delete.contains("account%20IN"), "{delete}");
    assert!(head(REQUESTS_BEFORE_INSERT)?.contains("INSERT"));
    assert!(seen
        .iter()
        .all(|request| request.lines().next().is_some_and(|line| !line.contains(PASSWORD))));
    assert!(seen
        .iter()
        .all(|request| request.to_lowercase().contains(&format!("x-clickhouse-key: {}", PASSWORD.to_lowercase()))));
    let insert = body_of(seen.get(REQUESTS_BEFORE_INSERT).ok_or("no insert")?);
    assert!(insert.lines().all(|line| line.contains("\"tenant\":\"acme\"")));
    assert_eq!(insert.lines().count(), JANUARY_ROWS);
    Ok(())
}


#[test]
fn a_rerun_of_the_same_file_sends_identical_rows() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let export = january()?;
    let again = january()?;
    let server = serve(rig.listener.try_clone()?, vec![OK; (REQUESTS_BEFORE_INSERT + 1) * TWICE]);
    load_table(&rig.config, &export, VERSION, &idle)?;
    load_table(&rig.config, &again, VERSION, &idle)?;
    let seen = joined(server)?;
    let first = body_of(seen.get(REQUESTS_BEFORE_INSERT).ok_or("no insert")?);
    let second = body_of(seen.get(REQUESTS_BEFORE_INSERT * TWICE + 1).ok_or("no insert")?);
    assert!(!first.is_empty());
    assert_eq!(first, second);
    Ok(())
}


#[test]
fn a_corrected_export_deletes_the_covered_days_before_inserting_its_own_source() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let original = january()?;
    let corrected = export_of(
        &["1.5,USD,acct,2026-01-05T10:00:00Z,compute,", "9.5,USD,acct,2026-01-07T10:00:00Z,compute,"],
        "acme",
    )?;
    assert_ne!(original.source, corrected.source);
    let server = serve(rig.listener.try_clone()?, vec![OK; (REQUESTS_BEFORE_INSERT + 1) * TWICE]);
    load_table(&rig.config, &original, VERSION, &idle)?;
    load_table(&rig.config, &corrected, VERSION, &idle)?;
    let seen = joined(server)?;
    let second_delete = seen.get(REQUESTS_BEFORE_INSERT + 1 + SCHEMA_REQUESTS).ok_or("no delete")?;
    assert!(second_delete.contains("DELETE"));
    assert!(second_delete.contains("param_tenant=acme"));
    assert!(second_delete.contains("param_accounts=%5B%27acct%27%5D"), "{second_delete}");
    let second_insert = body_of(seen.get(REQUESTS_BEFORE_INSERT * TWICE + 1).ok_or("no insert")?);
    assert!(second_insert.contains(&corrected.source));
    assert!(!second_insert.contains(&original.source));
    assert!(second_insert.contains("\"cost\":\"9.5\""));
    Ok(())
}


#[test]
fn another_tenant_deletes_only_its_own_rows() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    rig.config.tenant = "globex".to_owned();
    let server = serve(rig.listener.try_clone()?, vec![OK; REQUESTS_BEFORE_INSERT + 1]);
    let other = export_of(&["1,USD,acct,2026-01-05T10:00:00Z,compute,"], "globex")?;
    load_table(&rig.config, &other, VERSION, &idle)?;
    let seen = joined(server)?;
    let delete = seen.get(SCHEMA_REQUESTS).ok_or("no delete")?;
    assert!(delete.contains("param_tenant=globex"));
    assert!(!delete.contains("acme"));
    Ok(())
}


#[test]
fn the_delete_names_every_account_of_the_export_and_no_other() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; REQUESTS_BEFORE_INSERT + 1]);
    let export = export_of(
        &["1,USD,acct2,2026-01-06T10:00:00Z,compute,", "2,USD,it's,2026-01-06T10:00:00Z,compute,"],
        "acme",
    )?;
    load_table(&rig.config, &export, VERSION, &idle)?;
    let seen = joined(server)?;
    let delete = seen.get(SCHEMA_REQUESTS).ok_or("no delete")?;
    assert!(delete.contains("param_accounts=%5B%27acct2%27%2C%27it%5C%27s%27%5D"), "{delete}");
    assert!(!delete.contains("acct1"), "{delete}");
    Ok(())
}


#[test]
fn too_many_accounts_are_refused_before_any_io() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    fs::remove_file(&rig.config.password_file)?;
    let wide = wide_export()?;
    let first_day = wide.table.day_totals.keys().next().copied().ok_or("no day")?;
    let accounts = (0..=MAX_REPLACE_ACCOUNTS)
        .map(|number| {
            (
                (first_day, format!("a{number}"), "total", String::new(), String::new()),
                rust_decimal::Decimal::ONE,
            )
        })
        .collect();
    let many = Export {
        table: CostTable {
            account_rows: accounts,
            ..wide.table.clone()
        },
        source: wide.source.clone(),
    };
    assert!(matches!(load_table(&rig.config, &many, VERSION, &idle), Err(LoadError::TooManyAccounts)));
    let long = Export {
        table: CostTable {
            account_rows: [(
                (
                    first_day,
                    "x".repeat(MAX_REPLACE_ACCOUNT_BYTES + 1),
                    "total",
                    String::new(),
                    String::new(),
                ),
                rust_decimal::Decimal::ONE,
            )]
            .into_iter()
            .collect(),
            ..wide.table
        },
        source: wide.source,
    };
    assert!(matches!(load_table(&rig.config, &long, VERSION, &idle), Err(LoadError::TooManyAccounts)));
    rig.config.tenant = "acme".to_owned();
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_tenant_mismatch_is_refused_before_any_io() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    rig.config.tenant = "globex".to_owned();
    fs::remove_file(&rig.config.password_file)?;
    let failed = load_table(&rig.config, &january()?, VERSION, &idle);
    assert!(matches!(failed, Err(LoadError::TenantMismatch)));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn invalid_settings_are_refused_before_any_io() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    rig.config.tenant = "-x".to_owned();
    fs::remove_file(&rig.config.password_file)?;
    let failed = load_table(&rig.config, &january()?, VERSION, &idle);
    assert!(matches!(failed, Err(LoadError::Settings(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_quote_in_the_tenant_is_refused_before_any_io() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    rig.config.tenant = "a'b".to_owned();
    let failed = load_table(&rig.config, &january()?, VERSION, &idle);
    assert!(matches!(failed, Err(LoadError::Settings(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn an_empty_export_sends_nothing() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let empty = export_of(&[], "acme")?;
    let outcome = load_table(&rig.config, &empty, VERSION, &idle)?;
    assert_eq!(outcome, LoadOutcome::default());
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let spent = || ONE_HOUR;
    assert!(matches!(
        load_table(&rig.config, &january()?, VERSION, &spent),
        Err(LoadError::Schema(InsertClass::Timeout))
    ));
    assert!(untouched(&rig.listener)?);
    let calls = Cell::new(0);
    let late = || {
        calls.set(calls.get() + 1);
        if calls.get() > SCHEMA_REQUESTS {
            ONE_HOUR
        } else {
            Duration::ZERO
        }
    };
    rig.listener.set_nonblocking(false)?;
    let server = serve(rig.listener.try_clone()?, vec![OK; SCHEMA_REQUESTS]);
    let failed = load_table(&rig.config, &january()?, VERSION, &late);
    assert!(matches!(failed, Err(LoadError::Replace(InsertClass::Timeout))));
    assert_eq!(joined(server)?.len(), SCHEMA_REQUESTS);
    let after_delete = Cell::new(0);
    let last = || {
        after_delete.set(after_delete.get() + 1);
        if after_delete.get() > REQUESTS_BEFORE_INSERT {
            ONE_HOUR
        } else {
            Duration::ZERO
        }
    };
    let second = serve(rig.listener.try_clone()?, vec![OK; REQUESTS_BEFORE_INSERT]);
    let outcome = load_table(&rig.config, &january()?, VERSION, &last)?;
    assert_eq!(outcome.failure.map(|failure| failure.class), Some(InsertClass::Timeout));
    assert_eq!(joined(second)?.len(), REQUESTS_BEFORE_INSERT);
    Ok(())
}


#[test]
fn a_server_that_never_answers_hits_the_deadline() -> TestResult {
    let rig = rig(STALL_TIMEOUT_MS)?;
    let (release, held) = channel();
    let server = stall(rig.listener.try_clone()?, held);
    let failed = load_table(&rig.config, &january()?, VERSION, &idle);
    release.send(())?;
    joined(server)?;
    assert!(matches!(failed, Err(LoadError::Schema(InsertClass::Timeout))));
    Ok(())
}


#[test]
fn refusals_are_classified_without_reading_the_message() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec!["401 Unauthorized"]);
    let failed = load_table(&rig.config, &january()?, VERSION, &idle);
    assert!(matches!(failed, Err(LoadError::Schema(InsertClass::Unauthorized))));
    joined(server)?;
    let delete_refused = serve(rig.listener.try_clone()?, vec![OK, OK, SERVER_ERROR]);
    let replace = load_table(&rig.config, &january()?, VERSION, &idle);
    assert!(matches!(replace, Err(LoadError::Replace(InsertClass::Unavailable))));
    joined(delete_refused)?;
    let insert_refused = serve(rig.listener.try_clone()?, vec![OK, OK, OK, "302 Found"]);
    let outcome = load_table(&rig.config, &january()?, VERSION, &idle)?;
    assert_eq!(outcome.failure.map(|failure| failure.class), Some(InsertClass::Rejected));
    assert_eq!(outcome.batches_planned, 1);
    joined(insert_refused)?;
    Ok(())
}


fn wide_export() -> Result<Export, Box<dyn Error>> {
    let first = export_of(&["1,USD,a,2026-01-05T00:00:00Z,s,"], "acme")?;
    let table = CostTable {
        account_rows: (0..=ROWS_PER_BATCH)
            .map(|number| {
                (
                    first.table.day_totals.keys().next().copied().unwrap_or(time::Date::MIN),
                    "a".to_owned(),
                    "account_service",
                    format!("s{number}"),
                    String::new(),
                )
            })
            .map(|key| (key, rust_decimal::Decimal::ONE))
            .collect(),
        ..first.table
    };
    Ok(Export { source: first.source, table })
}


#[test]
fn a_failed_second_batch_is_reported_with_the_first_as_stored() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let server = serve(rig.listener.try_clone()?, vec![OK, OK, OK, OK, SERVER_ERROR]);
    let outcome = load_table(&rig.config, &wide_export()?, VERSION, &idle)?;
    assert_eq!(outcome.rows_per_batch, vec![ROWS_PER_BATCH]);
    assert_eq!(outcome.batches_planned, SCHEMA_REQUESTS);
    assert_eq!(
        outcome.failure,
        Some(BatchFailure {
            index: 1,
            rows: SECOND_BATCH_ROWS,
            class: InsertClass::Unavailable
        })
    );
    joined(server)?;
    Ok(())
}


#[test]
fn password_and_ca_files_are_bounded_and_checked() -> TestResult {
    let mut rig = rig(LONG_TIMEOUT_MS)?;
    fs::write(&rig.config.password_file, vec![b'a'; OVER_PASSWORD])?;
    assert!(matches!(
        load_table(&rig.config, &january()?, VERSION, &idle),
        Err(LoadError::Password(_))
    ));
    fs::write(&rig.config.password_file, NOT_UTF8)?;
    assert!(matches!(
        load_table(&rig.config, &january()?, VERSION, &idle),
        Err(LoadError::PasswordEncoding(_))
    ));
    fs::write(&rig.config.password_file, PASSWORD)?;
    let fifo = rig.dir.path().join("ca.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    rig.config.ca_file = Some(fifo);
    assert!(matches!(agent_for(&rig.config), Err(LoadError::CaFile(_))));
    let link = rig.dir.path().join("ca.link");
    assert!(Command::new("ln").arg("-s").arg("/dev/zero").arg(&link).status()?.success());
    rig.config.ca_file = Some(link);
    assert!(matches!(agent_for(&rig.config), Err(LoadError::CaFile(_))));
    let big = rig.dir.path().join("ca.big");
    fs::write(&big, vec![b'a'; usize::try_from(MAX_CA_BYTES)? + 1])?;
    rig.config.ca_file = Some(big);
    assert!(matches!(load_table(&rig.config, &january()?, VERSION, &idle), Err(LoadError::CaFile(_))));
    let junk = rig.dir.path().join("ca.junk");
    fs::write(&junk, "not a certificate")?;
    rig.config.ca_file = Some(junk);
    assert!(matches!(agent_for(&rig.config), Err(LoadError::Agent(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_zero_remaining_budget_posts_nothing() -> TestResult {
    let rig = rig(LONG_TIMEOUT_MS)?;
    let agent = agent_for(&rig.config)?;
    let statement = Statement {
        text: "SELECT 1".to_owned(),
        params: Vec::new(),
        body: String::new(),
    };
    assert_eq!(
        post(&agent, &rig.config, PASSWORD, &statement, Duration::ZERO),
        Some(InsertClass::Timeout)
    );
    assert!(untouched(&rig.listener)?);
    Ok(())
}
