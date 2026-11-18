#[path = "common/fetch/types.rs"]
mod types;


use cloud_cost::fetch::{
    fetch_new, fetch_source, gunzip_capped, key_digest, load_class, merge_reports, parse_credentials, read_credentials, DIGEST_CHARS,
    MAX_CREDENTIAL_BYTES,
};
use cloud_cost::fetch_error::{FetchError, HttpClass, HttpFailure, LedgerFailure, Refusal};
use cloud_cost::fetch_model::{
    FetchEnv, FetchReport, FetchSettings, FetchSource, HttpRequest, HttpResponse, DEFAULT_FETCH_TIMEOUT_MS, DEFAULT_MAX_OBJECTS,
};
use cloud_cost::ledger::{is_loaded, record_loaded, INSERT_OBJECT, LEDGER_DDL, SELECT_OBJECT};
use cloud_cost::listing::MAX_LIST_BYTES;
use cloud_cost::load::{BatchFailure, LoadError, LoadOutcome};
use cloud_cost::model::Limits;
use cloud_cost::source::Export;
use cloud_cost::transport::send;
use flate2::write::GzEncoder;
use flate2::Compression;
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use siem_ingest::error::{InsertClass, InsertError};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread::spawn;
use tempfile::{tempdir, TempDir};
use types::Reply;
use types::TestResult;
use url::Url;


const HEADER: &str = "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags";


const MARKER: &str = "MARKER-7f3a91c2";


const NOW: u64 = 1_700_000_000_000;


const SMALL_LIMIT: u64 = 2000;


const BOMB_BYTES: usize = 1_048_576;


const REQUEST_BUFFER: usize = 8192;


const STATUS_OK: u16 = 200;


const STATUS_NOT_FOUND: u16 = 404;


const STATUS_ERROR: u16 = 500;


const STATUS_FORBIDDEN: u16 = 403;


const THREE: usize = 3;


const IDENTITY_FIELDS: usize = 4;


const KEY_FIELD: usize = 2;


const DIGEST_FIELD: usize = 5;


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
const OPEN_MODE: u32 = 0o644;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const TINY_LIMIT: u64 = 2;


const TWO: usize = 2;


fn ok(body: &[u8]) -> Reply {
    Ok(HttpResponse {
        status: STATUS_OK,
        body: body.to_vec(),
    })
}


fn status(code: u16, body: &str) -> Reply {
    Ok(HttpResponse {
        status: code,
        body: body.as_bytes().to_vec(),
    })
}


fn entry(key: &str, etag: &str) -> String {
    format!("<Contents><Key>{key}</Key><ETag>&quot;{etag}&quot;</ETag><Size>1</Size></Contents>")
}


fn page(parts: &[String], token: Option<&str>) -> String {
    let tail = token.map_or(String::new(), |next| {
        format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{next}</NextContinuationToken>")
    });
    format!(
        "<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><EncodingType>url</EncodingType>{}{tail}</ListBucketResult>",
        parts.concat()
    )
}


fn csv(lines: &[&str]) -> String {
    format!("{HEADER}\n{}\n", lines.join("\n"))
}


fn january(account: &str) -> String {
    csv(&[&format!("1.5,USD,{account},2026-01-05T10:00:00Z,compute,")])
}


fn gzip(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}


fn digest_of(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}


#[derive(Default)]
struct Fake {
    pages: BTreeMap<String, Reply>,
    objects: BTreeMap<String, Reply>,
    requested: RefCell<Vec<String>>,
    lists: Cell<usize>,
}


fn serve(fake: &Fake, request: &HttpRequest) -> Reply {
    let url = Url::parse(&request.url).map_err(|_refused| HttpFailure(HttpClass::Other))?;
    let query: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    if query.contains_key("list-type") {
        fake.lists.set(fake.lists.get() + 1);
        fake.pages
            .get(query.get("continuation-token").map_or("", String::as_str))
            .cloned()
            .unwrap_or(Err(HttpFailure(HttpClass::Other)))
    } else {
        let decoded = percent_decode_str(url.path())
            .decode_utf8()
            .map_err(|_refused| HttpFailure(HttpClass::Other))?;
        let key = decoded.strip_prefix("/billing/").unwrap_or("").to_owned();
        fake.requested.borrow_mut().push(key.clone());
        fake.objects.get(&key).cloned().unwrap_or(Err(HttpFailure(HttpClass::Other)))
    }
}


#[derive(Default)]
struct Ledger {
    rows: RefCell<BTreeSet<Vec<String>>>,
    calls: RefCell<Vec<(String, Vec<String>)>>,
    fail_select: Cell<bool>,
    fail_insert: Cell<bool>,
}


fn exec(ledger: &Ledger, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, LedgerFailure> {
    ledger.calls.borrow_mut().push((sql.to_owned(), params.to_vec()));
    let identity: Vec<String> = params.iter().take(IDENTITY_FIELDS).cloned().collect();
    if sql == SELECT_OBJECT {
        if ledger.fail_select.get() {
            Err(LedgerFailure)
        } else if ledger.rows.borrow().contains(&identity) {
            Ok(identity.get(KEY_FIELD).cloned().map_or_else(Vec::new, |key| vec![vec![key]]))
        } else {
            Ok(Vec::new())
        }
    } else if ledger.fail_insert.get() {
        Err(LedgerFailure)
    } else {
        ledger.rows.borrow_mut().insert(identity);
        Ok(Vec::new())
    }
}


#[derive(Clone, Copy)]
enum LoadMode {
    Accept,
    Fail,
    Partial,
}


struct Loads {
    calls: RefCell<Vec<(String, String)>>,
    mode: Cell<LoadMode>,
}


fn load(loads: &Loads, tenant: &str, export: &Export) -> Result<LoadOutcome, LoadError> {
    loads.calls.borrow_mut().push((tenant.to_owned(), export.source.clone()));
    match loads.mode.get() {
        LoadMode::Accept => Ok(LoadOutcome::default()),
        LoadMode::Fail => Err(LoadError::TenantMismatch),
        LoadMode::Partial => Ok(LoadOutcome {
            failure: Some(BatchFailure {
                index: 0,
                rows: 0,
                class: InsertClass::Timeout,
            }),
            ..LoadOutcome::default()
        }),
    }
}


struct Rig {
    dir: TempDir,
    ledger: Ledger,
    loads: Loads,
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    let rig = Rig {
        dir: tempdir()?,
        ledger: Ledger::default(),
        loads: Loads {
            calls: RefCell::new(Vec::new()),
            mode: Cell::new(LoadMode::Accept),
        },
    };
    ["acme", "globex"]
        .iter()
        .try_for_each(|tenant| write_credentials(rig.dir.path(), tenant, "AKIATEST\nSECRETTEST\n"))?;
    Ok(rig)
}


#[cfg(unix)]
fn write_secret(path: &Path, content: &[u8]) -> io::Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: &Path, content: &[u8]) -> io::Result<()> {
    fs::write(path, content)
}


fn write_credentials(dir: &Path, tenant: &str, content: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join(tenant))?;
    Ok(write_secret(&dir.join(tenant).join("s3.key"), content.as_bytes())?)
}


fn source(id: &str, tenant: &str) -> FetchSource {
    FetchSource {
        id: id.to_owned(),
        tenant: tenant.to_owned(),
        endpoint: "https://s3.example.test".to_owned(),
        region: "garage".to_owned(),
        bucket: "billing".to_owned(),
        prefix: "p/".to_owned(),
        credentials: format!("{tenant}/s3.key"),
        ca_file: None,
        max_objects_per_run: DEFAULT_MAX_OBJECTS,
        timeout_ms: DEFAULT_FETCH_TIMEOUT_MS,
    }
}


fn settings(rig: &Rig, sources: Vec<FetchSource>) -> FetchSettings {
    FetchSettings {
        secrets_dir: rig.dir.path().to_path_buf(),
        sources,
    }
}


fn round(rig: &Rig, settings: &FetchSettings, fake: &Fake, limits: &Limits) -> FetchReport {
    let http = |request: &HttpRequest| serve(fake, request);
    let executor = |sql: &str, params: &[String]| exec(&rig.ledger, sql, params);
    let loader = |tenant: &str, export: &Export| load(&rig.loads, tenant, export);
    let env = FetchEnv {
        http: &http,
        exec: &executor,
        load: &loader,
        limits,
    };
    fetch_new(settings, &env, NOW)
}


fn with_objects(entries: &[(&str, &str, Reply)], token: Option<&str>) -> Fake {
    let mut fake = Fake::default();
    let parts: Vec<String> = entries.iter().map(|(key, etag, _)| entry(key, etag)).collect();
    fake.pages.insert(String::new(), ok(page(&parts, token).as_bytes()));
    entries.iter().for_each(|(key, _, body)| {
        fake.objects.insert((*key).to_owned(), body.clone());
    });
    fake
}


fn chain(error: &(dyn Error + 'static)) -> String {
    let mut text = format!("{error} {error:?}");
    let mut next = error.source();
    (0..THREE * THREE).for_each(|_step| {
        if let Some(found) = next {
            text.push_str(&format!(" {found} {found:?}"));
            next = found.source();
        }
    });
    text
}


#[test]
fn only_the_new_csv_is_fetched_across_two_pages() -> TestResult {
    let rig = rig()?;
    rig.ledger
        .rows
        .borrow_mut()
        .insert(vec!["acme".to_owned(), "main".to_owned(), "p/old.csv".to_owned(), "\"e1\"".to_owned()]);
    let mut fake = Fake::default();
    fake.pages.insert(
        String::new(),
        ok(page(&[entry("p/old.csv", "e1"), entry("other/x.csv", "e1")], Some("t2")).as_bytes()),
    );
    fake.pages.insert(
        "t2".to_owned(),
        ok(page(&[entry("p/tool.exe", "e1"), entry("p/new.csv", "e2")], None).as_bytes()),
    );
    fake.objects.insert("p/new.csv".to_owned(), ok(january("acct").as_bytes()));
    let report = round(&rig, &settings(&rig, vec![source("main", "acme")]), &fake, &Limits::default());
    assert_eq!(
        (report.listed, report.skipped_key, report.already_loaded, report.loaded),
        (TWO, TWO, 1, 1)
    );
    assert!(report.refused.is_empty() && report.failed_sources.is_empty());
    assert_eq!(fake.requested.borrow().clone(), vec!["p/new.csv".to_owned()]);
    assert_eq!(fake.lists.get(), TWO);
    assert_eq!(
        rig.loads.calls.borrow().clone(),
        vec![("acme".to_owned(), digest_of(january("acct").as_bytes()))]
    );
    Ok(())
}


#[test]
fn a_rewritten_object_is_fetched_again_and_keeps_one_source_digest() -> TestResult {
    let rig = rig()?;
    let configured = settings(&rig, vec![source("main", "acme")]);
    let first = with_objects(&[("p/a.csv", "e1", ok(january("acct").as_bytes()))], None);
    assert_eq!(round(&rig, &configured, &first, &Limits::default()).loaded, 1);
    let again = round(&rig, &configured, &first, &Limits::default());
    assert_eq!((again.loaded, again.already_loaded), (0, 1));
    let rewritten = with_objects(&[("p/a.csv", "e2", ok(january("acct").as_bytes()))], None);
    assert_eq!(round(&rig, &configured, &rewritten, &Limits::default()).loaded, 1);
    let calls = rig.loads.calls.borrow().clone();
    assert_eq!(calls.len(), TWO);
    assert_eq!(calls.first(), calls.get(1));
    assert_eq!(rig.ledger.rows.borrow().len(), TWO);
    Ok(())
}


#[test]
fn a_gzip_object_is_loaded_under_the_digest_of_its_plain_bytes() -> TestResult {
    let rig = rig()?;
    let plain = january("acct");
    let fake = with_objects(&[("p/a.csv.gz", "e1", ok(&gzip(plain.as_bytes())?))], None);
    let report = round(&rig, &settings(&rig, vec![source("main", "acme")]), &fake, &Limits::default());
    assert_eq!(report.loaded, 1);
    assert_eq!(
        rig.loads.calls.borrow().first().map(|(_, digest)| digest.clone()),
        Some(digest_of(plain.as_bytes()))
    );
    let recorded = rig
        .ledger
        .calls
        .borrow()
        .iter()
        .find(|(sql, _)| sql == INSERT_OBJECT)
        .map(|(_, params)| params.clone());
    assert_eq!(
        recorded.as_ref().and_then(|params| params.get(DIGEST_FIELD)),
        Some(&digest_of(plain.as_bytes()))
    );
    Ok(())
}


#[test]
fn an_oversized_list_body_refuses_the_round_before_any_fetch() -> TestResult {
    let rig = rig()?;
    let mut fake = Fake::default();
    fake.pages.insert(String::new(), ok(&vec![b'x'; usize::try_from(MAX_LIST_BYTES)? + 1]));
    let report = round(&rig, &settings(&rig, vec![source("main", "acme")]), &fake, &Limits::default());
    assert!(matches!(report.failed_sources.as_slice(), [(id, FetchError::ListTooLarge)] if id == "main"));
    assert!(fake.requested.borrow().is_empty());
    Ok(())
}


#[test]
fn an_oversized_object_and_a_gzip_bomb_are_refused_alone() -> TestResult {
    let rig = rig()?;
    let limits = Limits {
        max_bytes: SMALL_LIMIT,
        ..Limits::default()
    };
    let big = "x".repeat(usize::try_from(SMALL_LIMIT)? + 1);
    let bomb = gzip(&vec![b'0'; BOMB_BYTES])?;
    assert!(bomb.len() < usize::try_from(SMALL_LIMIT)?);
    let fake = with_objects(
        &[
            ("p/big.csv", "e", ok(big.as_bytes())),
            ("p/bomb.csv.gz", "e", ok(&bomb)),
            ("p/bad.csv.gz", "e", ok(b"not gzip")),
            ("p/good.csv", "e", ok(january("acct").as_bytes())),
        ],
        None,
    );
    let report = round(&rig, &settings(&rig, vec![source("main", "acme")]), &fake, &limits);
    assert_eq!(report.loaded, 1);
    let reasons: Vec<Refusal> = report.refused.iter().map(|(_, reason)| *reason).collect();
    assert_eq!(reasons, vec![Refusal::TooLarge, Refusal::TooLarge, Refusal::BadGzip]);
    Ok(())
}


#[test]
fn every_object_failure_is_one_refusal_and_never_reaches_the_ledger() -> TestResult {
    let rig = rig()?;
    let configured = settings(&rig, vec![source("main", "acme")]);
    let fake = with_objects(
        &[
            ("p/missing.csv", "e", status(STATUS_NOT_FOUND, MARKER)),
            ("p/down.csv", "e", Err(HttpFailure(HttpClass::Timeout))),
            ("p/columns.csv", "e", ok(b"a,b\n1,2\n")),
            ("p/load.csv", "e", ok(january("acct").as_bytes())),
        ],
        None,
    );
    rig.loads.mode.set(LoadMode::Fail);
    let report = round(&rig, &configured, &fake, &Limits::default());
    let reasons: Vec<Refusal> = report.refused.iter().map(|(_, reason)| *reason).collect();
    assert_eq!(
        reasons,
        vec![
            Refusal::Status(STATUS_NOT_FOUND),
            Refusal::Transport(HttpClass::Timeout),
            Refusal::Unreadable,
            Refusal::Load(None)
        ]
    );
    rig.loads.mode.set(LoadMode::Partial);
    let partial = round(&rig, &configured, &fake, &Limits::default());
    assert_eq!(
        partial.refused.last().map(|(_, reason)| *reason),
        Some(Refusal::Load(Some(InsertClass::Timeout)))
    );
    assert!(rig.ledger.rows.borrow().is_empty());
    assert!(!format!("{report:?}{partial:?}").contains(MARKER));
    Ok(())
}


#[test]
fn a_ledger_failure_is_a_refusal_and_a_lost_write_is_retried_next_round() -> TestResult {
    let rig = rig()?;
    let configured = settings(&rig, vec![source("main", "acme")]);
    let fake = with_objects(&[("p/a.csv", "e", ok(january("acct").as_bytes()))], None);
    rig.ledger.fail_select.set(true);
    let blind = round(&rig, &configured, &fake, &Limits::default());
    assert_eq!(blind.refused.first().map(|(_, reason)| *reason), Some(Refusal::Ledger));
    assert!(rig.loads.calls.borrow().is_empty());
    rig.ledger.fail_select.set(false);
    rig.ledger.fail_insert.set(true);
    let unwritten = round(&rig, &configured, &fake, &Limits::default());
    assert_eq!(unwritten.refused.first().map(|(_, reason)| *reason), Some(Refusal::Ledger));
    rig.ledger.fail_insert.set(false);
    assert_eq!(round(&rig, &configured, &fake, &Limits::default()).loaded, 1);
    assert_eq!(rig.loads.calls.borrow().len(), TWO);
    Ok(())
}


#[test]
fn a_credentials_reference_of_another_tenant_is_refused_before_any_request() -> TestResult {
    let rig = rig()?;
    let mut stolen = source("main", "acme");
    stolen.credentials = "globex/s3.key".to_owned();
    let fake = with_objects(&[("p/a.csv", "e", ok(january("acct").as_bytes()))], None);
    let report = round(&rig, &settings(&rig, vec![stolen]), &fake, &Limits::default());
    assert!(matches!(report.failed_sources.as_slice(), [(_, FetchError::Settings("credentials"))]));
    assert_eq!((fake.lists.get(), rig.ledger.calls.borrow().len()), (0, 0));
    Ok(())
}


#[test]
fn two_tenants_load_their_own_rows_and_their_own_ledger_entries() -> TestResult {
    let rig = rig()?;
    let fake = with_objects(&[("p/a.csv", "e", ok(january("acct").as_bytes()))], None);
    let acme_only = settings(&rig, vec![source("main", "acme")]);
    assert_eq!(round(&rig, &acme_only, &fake, &Limits::default()).loaded, 1);
    let both = settings(&rig, vec![source("main", "acme"), source("second", "globex")]);
    let report = round(&rig, &both, &fake, &Limits::default());
    assert_eq!((report.already_loaded, report.loaded), (1, 1));
    let tenants: Vec<String> = rig.loads.calls.borrow().iter().map(|(tenant, _)| tenant.clone()).collect();
    assert_eq!(tenants, vec!["acme".to_owned(), "globex".to_owned()]);
    let first_params: BTreeSet<String> = rig
        .ledger
        .calls
        .borrow()
        .iter()
        .filter_map(|(_, params)| params.first().cloned())
        .collect();
    assert_eq!(first_params, BTreeSet::from(["acme".to_owned(), "globex".to_owned()]));
    Ok(())
}


#[test]
fn the_per_run_cap_defers_the_rest_and_the_page_cap_is_reported() -> TestResult {
    let rig = rig()?;
    let mut capped = source("main", "acme");
    capped.max_objects_per_run = TWO;
    let body = january("acct");
    let fake = with_objects(
        &[
            ("p/a.csv", "e", ok(body.as_bytes())),
            ("p/b.csv", "e", ok(body.as_bytes())),
            ("p/c.csv", "e", ok(body.as_bytes())),
        ],
        None,
    );
    let report = round(&rig, &settings(&rig, vec![capped]), &fake, &Limits::default());
    assert_eq!((report.loaded, report.deferred), (TWO, 1));
    let mut endless = Fake::default();
    endless
        .pages
        .insert(String::new(), ok(page(&[entry("p/a.csv", "e")], Some("again")).as_bytes()));
    endless
        .pages
        .insert("again".to_owned(), ok(page(&[entry("p/a.csv", "e")], Some("again")).as_bytes()));
    let truncated = round(&rig, &settings(&rig, vec![source("main", "acme")]), &endless, &Limits::default());
    assert_eq!(truncated.incomplete_listings, 1);
    Ok(())
}


#[test]
fn a_failed_source_does_not_stop_the_others() -> TestResult {
    let rig = rig()?;
    let mut broken = source("broken", "acme");
    broken.bucket = "UPPER".to_owned();
    let fake = with_objects(&[("p/a.csv", "e", ok(january("acct").as_bytes()))], None);
    let report = round(&rig, &settings(&rig, vec![broken, source("main", "globex")]), &fake, &Limits::default());
    assert_eq!(report.loaded, 1);
    assert!(matches!(report.failed_sources.as_slice(), [(id, FetchError::Settings("bucket"))] if id == "broken"));
    Ok(())
}


#[test]
fn refused_objects_are_named_by_a_digest_of_their_key() -> TestResult {
    let rig = rig()?;
    let fake = with_objects(&[("p/secret-name.csv", "e", status(STATUS_ERROR, MARKER))], None);
    let report = round(&rig, &settings(&rig, vec![source("main", "acme")]), &fake, &Limits::default());
    let digest = key_digest("p/secret-name.csv");
    assert_eq!(digest.len(), DIGEST_CHARS);
    assert_eq!(report.refused, vec![(digest, Refusal::Status(STATUS_ERROR))]);
    assert!(!format!("{report:?}").contains("secret-name"));
    Ok(())
}


#[test]
fn credential_files_are_checked_and_bounded() -> TestResult {
    let dir = tempdir()?;
    write_credentials(dir.path(), "acme", "AKIATEST\nSECRETTEST\n")?;
    let path = dir.path().join("acme").join("s3.key");
    assert!(read_credentials(&path).is_ok());
    assert!(matches!(
        read_credentials(&dir.path().join("acme").join("absent")),
        Err(FetchError::Credentials(_))
    ));
    write_secret(&path, &NOT_UTF8)?;
    assert!(matches!(
        read_credentials(&path),
        Err(FetchError::CredentialsRead(io::ErrorKind::InvalidData))
    ));
    write_secret(
        &path,
        format!("{}\nsecret\n", "k".repeat(usize::try_from(MAX_CREDENTIAL_BYTES)?)).as_bytes(),
    )?;
    assert!(matches!(read_credentials(&path), Err(FetchError::BadCredentials)));
    let refused = [
        "",
        "only-one-line",
        "a\nb\nc",
        "\nsecret",
        "key\n\n",
        "ke y\nsecret",
        "key\nsec\u{3164}ret",
    ];
    refused
        .iter()
        .for_each(|text| assert!(matches!(parse_credentials(text), Err(FetchError::BadCredentials)), "{text:?}"));
    let oversized = format!("{}\nsecret", "k".repeat(usize::try_from(MAX_CREDENTIAL_BYTES)?));
    assert!(matches!(parse_credentials(&oversized), Err(FetchError::BadCredentials)));
    assert!(parse_credentials("key\nsecret").is_ok());
    assert!(parse_credentials("key\r\nsecret\r\n").is_ok());
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_credentials_file_open_to_others_is_refused() -> TestResult {
    let rig = rig()?;
    let path = rig.dir.path().join("acme").join("s3.key");
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(OPEN_MODE))?;
    assert!(matches!(read_credentials(&path), Err(FetchError::Credentials(_))));
    Ok(())
}


#[test]
fn gunzip_is_capped_at_the_limit() -> TestResult {
    let small = gzip(b"abc")?;
    assert_eq!(gunzip_capped(&small, SMALL_LIMIT), Ok(b"abc".to_vec()));
    assert_eq!(gunzip_capped(&small, TINY_LIMIT), Err(Refusal::TooLarge));
    assert_eq!(gunzip_capped(b"plain", SMALL_LIMIT), Err(Refusal::BadGzip));
    Ok(())
}


#[test]
fn reports_merge_and_the_ledger_binds_the_tenant_first() -> TestResult {
    let merged = merge_reports(
        FetchReport {
            loaded: 1,
            refused: vec![("d".to_owned(), Refusal::Load(None))],
            ..FetchReport::default()
        },
        FetchReport {
            loaded: 1,
            failed_sources: vec![("s".to_owned(), FetchError::Bucket)],
            ..FetchReport::default()
        },
    );
    assert_eq!((merged.loaded, merged.refused.len(), merged.failed_sources.len()), (TWO, 1, 1));
    let ledger = Ledger::default();
    let object = cloud_cost::fetch_model::ListedObject {
        key: "p/a.csv".to_owned(),
        etag: "e".to_owned(),
        size: 1,
    };
    let executor = |sql: &str, params: &[String]| exec(&ledger, sql, params);
    assert!(!is_loaded(&executor, "acme", "main", &object)?);
    record_loaded(&executor, "acme", "main", &object, "sha", NOW)?;
    assert!(is_loaded(&executor, "acme", "main", &object)?);
    assert!(!is_loaded(&executor, "globex", "main", &object)?);
    assert!(ledger
        .calls
        .borrow()
        .iter()
        .all(|(sql, params)| (sql == SELECT_OBJECT || sql == INSERT_OBJECT)
            && params.first().is_some_and(|tenant| tenant == "acme" || tenant == "globex")));
    assert!(LEDGER_DDL.contains("PRIMARY KEY (tenant, source_id, key, etag)"));
    Ok(())
}


#[test]
fn fetch_source_refuses_an_invalid_source_without_a_request() -> TestResult {
    let rig = rig()?;
    let fake = Fake::default();
    let http = |request: &HttpRequest| serve(&fake, request);
    let executor = |sql: &str, params: &[String]| exec(&rig.ledger, sql, params);
    let loader = |tenant: &str, export: &Export| load(&rig.loads, tenant, export);
    let limits = Limits::default();
    let env = FetchEnv {
        http: &http,
        exec: &executor,
        load: &loader,
        limits: &limits,
    };
    let mut invalid = source("main", "acme");
    invalid.prefix = "../x".to_owned();
    assert!(matches!(
        fetch_source(&settings(&rig, vec![]), &invalid, &env, NOW),
        Err(FetchError::Settings("prefix"))
    ));
    assert_eq!(fake.lists.get(), 0);
    Ok(())
}


struct Served {
    endpoint: String,
    handle: std::thread::JoinHandle<io::Result<()>>,
}


fn error_server(body: &'static str) -> Result<Served, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let handle = spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut buffer = [b' '; REQUEST_BUFFER];
        let _read = stream.read(&mut buffer)?;
        let reply = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes())
    });
    Ok(Served { endpoint, handle })
}


#[test]
fn an_s3_error_body_never_reaches_a_display_a_debug_or_a_source() -> TestResult {
    let rig = rig()?;
    let Served { endpoint, handle: server } = error_server("<Error><Code>AccessDenied</Code><Message>MARKER-7f3a91c2</Message></Error>")?;
    let mut local = source("main", "acme");
    local.endpoint = endpoint;
    let configured = settings(&rig, vec![local]);
    let http = |request: &HttpRequest| send(request);
    let executor = |sql: &str, params: &[String]| exec(&rig.ledger, sql, params);
    let loader = |tenant: &str, export: &Export| load(&rig.loads, tenant, export);
    let limits = Limits::default();
    let env = FetchEnv {
        http: &http,
        exec: &executor,
        load: &loader,
        limits: &limits,
    };
    let report = fetch_new(&configured, &env, NOW);
    server.join().map_err(|_| "server thread panicked")??;
    let failure = report.failed_sources.first().map(|(_, error)| error).ok_or("no failure")?;
    assert!(matches!(failure, FetchError::Status(STATUS_FORBIDDEN)));
    assert!(!chain(failure).contains(MARKER));
    assert!(!format!("{report:?}").contains(MARKER));
    Ok(())
}


#[test]
fn errors_keep_no_peer_text_in_their_chain() -> TestResult {
    let credentials = FetchError::Credentials(core_config::secret_file::SecretFileError::Mode { file: "f".to_owned() });
    assert!(chain(&credentials).contains("group or other"));
    assert!(!chain(&FetchError::Transport(HttpClass::Other)).contains(MARKER));
    Ok(())
}


#[test]
fn a_load_failure_keeps_only_its_class() -> TestResult {
    let replace = LoadError::Replace {
        done: 0,
        total: 1,
        class: InsertClass::Timeout,
    };
    assert_eq!(load_class(&replace), Some(InsertClass::Timeout));
    assert_eq!(load_class(&LoadError::Schema(InsertClass::Rejected)), Some(InsertClass::Rejected));
    assert_eq!(
        load_class(&LoadError::Agent(InsertError::Class(InsertClass::Unavailable))),
        Some(InsertClass::Unavailable)
    );
    assert_eq!(load_class(&LoadError::TenantMismatch), None);
    Ok(())
}
