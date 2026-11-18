#[path = "common/record.rs"]
mod record;
#[path = "common/store_fake.rs"]
mod store_fake;
#[path = "common/types.rs"]
mod types;


use cert_inventory::alerting::MAX_DNS_NAME_BYTES;
use cert_inventory::error::InventoryStoreError;
use cert_inventory::model::{CertFilter, CertRecord, KeyType, Source, SourceKind, StoreLimits};
use cert_inventory::parse::MAX_DNS_NAMES;
use cert_inventory::store::{
    cut_text, decode_cursor, doc_of, encode_cursor, key_type_text, kind_text, list_certificates, record_ok, sightings_of, source_ok, store_records,
    time_in_range, COL_DNS_NAMES, COL_FIRST_SEEN, COL_KEY_BITS, COL_KEY_TYPE, COL_LAST_SEEN, COL_NOT_AFTER, COL_NOT_BEFORE, COL_SELF_SIGNED,
    DEFAULT_LIMITS, MAX_PAGE, MAX_SOURCE_BYTES, MAX_STORE_BATCH, MAX_TEXT_BYTES, MIGRATIONS, MIGRATION_NAMESPACE,
};
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::tenant_scope;
use record::record_with;
use store_fake::{capture_dispatch, executor, fixed, Capture, Fake};
use tokio::sync::Barrier;
use types::TestResult;


const MIN_TIME: i64 = -62_167_219_200;


const NEGATIVE_TIME: i64 = -5;


const KEY_BITS: usize = 2048;


const NOW: i64 = 1_700_000_000;


const LATER: i64 = 1_700_086_400;


const FAR_FUTURE: i64 = 253_402_300_800;


const NOT_AFTER: i64 = 1_800_000_000;


const TIE_GROUP: i64 = 7;


const MANY: usize = 1_200;


const BIG_TEXT: usize = 1_000_000;


const HEX_WIDTH: usize = 64;


const SMALL_CAP: usize = 2;


const RECORDS_OVER_CAP: usize = 5;


const THREE: usize = 3;


const FOUR: usize = 4;


const BATCHES_OF_2500: usize = 2_500;


fn cert(index: usize, not_after: i64) -> CertRecord {
    let mut record = record_with(&["a.example.com"], not_after);
    record.fingerprint_sha256 = format!("{index:0HEX_WIDTH$x}");
    record.subject = format!("CN=host{index}.example.com");
    record.issuer = "CN=Test CA".to_owned();
    record
}


fn source(kind: SourceKind, reference: &str) -> Source {
    Source {
        kind,
        reference: reference.to_owned(),
    }
}


fn scan_source() -> Source {
    source(SourceKind::Scan, "host1:/etc/ssl/a.pem")
}


fn run<Work: std::future::Future>(future: Work) -> Result<Work::Output, std::io::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    Ok(runtime.block_on(future))
}


#[test]
fn two_tenants_with_one_fingerprint_keep_separate_rows() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let first = tenant_scope("a")?;
    let second = tenant_scope("b")?;
    let records = vec![cert(1, NOT_AFTER)];
    let counts_a = run(store_records(&exec, &first, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    let counts_b = run(store_records(&exec, &second, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    assert_eq!((counts_a.inserted, counts_b.inserted), (1, 1));
    let state = fake.state.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(state.certs.len(), SMALL_CAP);
    drop(state);
    let page_a = run(list_certificates(&exec, &first, &CertFilter::default(), None, MAX_PAGE))??;
    let none = run(list_certificates(&exec, &tenant_scope("c")?, &CertFilter::default(), None, MAX_PAGE))??;
    assert_eq!(page_a.certs.len(), 1);
    assert!(none.certs.is_empty());
    assert!(page_a.next_cursor.is_none());
    Ok(())
}


#[test]
fn a_rerun_moves_last_seen_only_and_a_forged_twin_changes_nothing() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let original = cert(1, NOT_AFTER);
    let first = run(store_records(
        &exec,
        &scope,
        &scan_source(),
        std::slice::from_ref(&original),
        NOW,
        &DEFAULT_LIMITS,
    ))??;
    let mut forged = original.clone();
    forged.subject = "CN=forged".to_owned();
    let second = run(store_records(&exec, &scope, &scan_source(), &[forged], LATER, &DEFAULT_LIMITS))??;
    assert_eq!((first.inserted, first.seen_again), (1, 0));
    assert_eq!((second.inserted, second.seen_again), (0, 1));
    let page = run(list_certificates(&exec, &scope, &CertFilter::default(), None, MAX_PAGE))??;
    let stored = page.certs.first().ok_or("no row")?;
    assert_eq!(stored.record.subject, original.subject);
    assert_eq!((stored.first_seen, stored.last_seen), (NOW, LATER));
    assert_eq!(stored.record.dns_names, original.dns_names);
    assert_eq!(stored.record.key_type, KeyType::Other);
    let sightings = run(sightings_of(&exec, &scope, &original.fingerprint_sha256))??;
    assert_eq!(sightings.len(), 1);
    assert_eq!(sightings.first().ok_or("none")?.last_seen, LATER);
    Ok(())
}


#[test]
fn a_cap_bounds_the_rows_with_one_warning_per_batch() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let limits = StoreLimits {
        max_certs: SMALL_CAP,
        max_sightings: MANY,
    };
    let records: Vec<CertRecord> = (1..=RECORDS_OVER_CAP).map(|index| cert(index, NOT_AFTER)).collect();
    let capture = Capture::default();
    let dispatch = capture_dispatch(&capture);
    let counts = tracing::dispatcher::with_default(&dispatch, || run(store_records(&exec, &scope, &scan_source(), &records, NOW, &limits)))??;
    assert_eq!((counts.inserted, counts.refused_full), (SMALL_CAP, THREE));
    let logged = String::from_utf8(capture.bytes.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    assert_eq!(logged.matches("caps reached").count(), 1);
    let again = run(store_records(&exec, &scope, &scan_source(), &records, LATER, &limits))??;
    assert_eq!((again.inserted, again.seen_again, again.refused_full), (0, SMALL_CAP, THREE));
    Ok(())
}


#[test]
fn a_sighting_cap_refuses_the_record_and_leaves_known_sightings() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let limits = StoreLimits {
        max_certs: MANY,
        max_sightings: 1,
    };
    let records = vec![cert(1, NOT_AFTER), cert(SMALL_CAP, NOT_AFTER)];
    let counts = run(store_records(&exec, &scope, &scan_source(), &records, NOW, &limits))??;
    assert_eq!((counts.inserted, counts.refused_full), (1, 1));
    let other = source(SourceKind::Ct, "ct.example.org");
    let blocked = run(store_records(
        &exec,
        &scope,
        &other,
        &records.iter().take(1).cloned().collect::<Vec<_>>(),
        NOW,
        &limits,
    ))??;
    assert_eq!(blocked.refused_full, 1);
    Ok(())
}


#[test]
fn two_concurrent_batches_never_exceed_the_cap() -> TestResult {
    let fake = Fake {
        gate: Some(Barrier::new(SMALL_CAP)),
        ..Fake::default()
    };
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let limits = StoreLimits {
        max_certs: FOUR,
        max_sightings: MANY,
    };
    let left: Vec<CertRecord> = (1..=THREE).map(|index| cert(index, NOT_AFTER)).collect();
    let right: Vec<CertRecord> = (FOUR..FOUR + THREE).map(|index| cert(index, NOT_AFTER)).collect();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let origin = scan_source();
    let (first, second) = runtime.block_on(async {
        tokio::join!(
            store_records(&exec, &scope, &origin, &left, NOW, &limits),
            store_records(&exec, &scope, &origin, &right, NOW, &limits)
        )
    });
    let total = first?.inserted + second?.inserted;
    assert_eq!(total, FOUR);
    assert_eq!(fake.state.lock().map_err(|_poisoned| "poisoned")?.certs.len(), FOUR);
    Ok(())
}


#[test]
fn a_cursor_walks_every_row_once_with_ties_on_not_after() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let records: Vec<CertRecord> = (1..=MANY).map(|index| cert(index, NOT_AFTER + (index as i64) / TIE_GROUP)).collect();
    run(store_records(&exec, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    let mut pending = true;
    while pending && pages < THREE {
        let page = run(list_certificates(&exec, &scope, &CertFilter::default(), cursor.as_deref(), MAX_PAGE))??;
        seen.extend(page.certs.iter().map(|stored| stored.record.fingerprint_sha256.clone()));
        cursor = page.next_cursor;
        pages += 1;
        pending = cursor.is_some();
    }
    assert!(cursor.is_none());
    assert_eq!(seen.len(), MANY);
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), MANY);
    let order: Vec<(i64, String)> = {
        let page = run(list_certificates(&exec, &scope, &CertFilter::default(), None, MAX_PAGE))??;
        page.certs
            .iter()
            .map(|stored| (stored.record.not_after, stored.record.fingerprint_sha256.clone()))
            .collect()
    };
    assert!(order.windows(SMALL_CAP).all(|pair| pair.first() < pair.get(1)));
    let cut = run(list_certificates(
        &exec,
        &scope,
        &CertFilter {
            expiring_before: Some(NOT_AFTER + 1),
        },
        None,
        MAX_PAGE,
    ))??;
    assert_eq!(cut.certs.len(), TIE_GROUP as usize - 1);
    Ok(())
}


#[test]
fn a_bad_source_is_refused_before_any_statement() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let records = vec![cert(1, NOT_AFTER), cert(SMALL_CAP, NOT_AFTER)];
    let long = "a".repeat(MAX_SOURCE_BYTES + 1);
    let bad = ["", "host\u{1b}[31m", "host\nx", "caf\u{e9}", "a b", "x;y", long.as_str()];
    bad.iter().try_for_each(|reference| -> TestResult {
        let counts = run(store_records(
            &exec,
            &scope,
            &source(SourceKind::Scan, reference),
            &records,
            NOW,
            &DEFAULT_LIMITS,
        ))??;
        assert_eq!((counts.refused_source, counts.inserted), (SMALL_CAP, 0));
        Ok(())
    })?;
    assert!(fake.state.lock().map_err(|_poisoned| "poisoned")?.statements.is_empty());
    assert!(source_ok(&source(SourceKind::Ct, "ct.example.org/logs/a-b_c:443@x+y=z,~%41")));
    assert!(source_ok(&source(SourceKind::Ct, &"a".repeat(MAX_SOURCE_BYTES))));
    Ok(())
}


#[test]
fn bad_records_are_refused_alone() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let good = cert(1, NOT_AFTER);
    let year_10000 = cert(SMALL_CAP, FAR_FUTURE);
    let mut early = cert(THREE, NOT_AFTER);
    early.not_before = i64::MIN;
    let mut nul = cert(FOUR, NOT_AFTER);
    nul.subject = "a\0b".to_owned();
    let mut nul_issuer = cert(FOUR + 1, NOT_AFTER);
    nul_issuer.issuer = "a\0b".to_owned();
    let mut name_nul = cert(FOUR + SMALL_CAP, NOT_AFTER);
    name_nul.dns_names = vec!["a\0b".to_owned()];
    let mut name_long = cert(FOUR + THREE, NOT_AFTER);
    name_long.dns_names = vec!["a".repeat(MAX_DNS_NAME_BYTES + 1)];
    let mut many_names = cert(FOUR + FOUR, NOT_AFTER);
    many_names.dns_names = vec!["a.example.com".to_owned(); MAX_DNS_NAMES + 1];
    let mut bad_fingerprint = cert(1, NOT_AFTER);
    bad_fingerprint.fingerprint_sha256 = "ABC".to_owned();
    let records = vec![good, year_10000, early, nul, nul_issuer, name_nul, name_long, many_names, bad_fingerprint];
    let counts = run(store_records(&exec, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    assert_eq!((counts.inserted, counts.refused_record), (1, records.len() - 1));
    assert!(time_in_range(MIN_TIME) && time_in_range(FAR_FUTURE - 1));
    assert!(!time_in_range(FAR_FUTURE) && !time_in_range(MIN_TIME - 1) && !time_in_range(i64::MAX));
    assert!(record_ok(&cert(1, NOT_AFTER)));
    Ok(())
}


#[test]
fn the_time_of_the_call_must_fit() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let refused = run(store_records(
        &exec,
        &scope,
        &scan_source(),
        &[cert(1, NOT_AFTER)],
        FAR_FUTURE,
        &DEFAULT_LIMITS,
    ))?;
    assert!(matches!(refused, Err(InventoryStoreError::BadNow)));
    let huge = StoreLimits {
        max_certs: usize::MAX,
        max_sightings: 1,
    };
    let too_big = run(store_records(&exec, &scope, &scan_source(), &[cert(1, NOT_AFTER)], NOW, &huge))?;
    assert!(matches!(too_big, Err(InventoryStoreError::BadLimit)));
    let sighting_huge = StoreLimits {
        max_certs: 1,
        max_sightings: usize::MAX,
    };
    let sighting_big = run(store_records(&exec, &scope, &scan_source(), &[cert(1, NOT_AFTER)], NOW, &sighting_huge))?;
    assert!(matches!(sighting_big, Err(InventoryStoreError::BadLimit)));
    Ok(())
}


#[test]
fn a_huge_subject_is_cut_visibly() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let mut record = cert(1, NOT_AFTER);
    record.subject = format!("CN=\u{1b}[31m\n{}", "x".repeat(BIG_TEXT));
    let total = record.subject.len();
    let counts = run(store_records(&exec, &scope, &scan_source(), &[record], NOW, &DEFAULT_LIMITS))??;
    assert_eq!(counts.inserted, 1);
    let page = run(list_certificates(&exec, &scope, &CertFilter::default(), None, 1))??;
    let stored = page.certs.first().ok_or("no row")?;
    assert!(stored.record.subject.len() < MAX_TEXT_BYTES + HEX_WIDTH);
    assert!(stored.record.subject.ends_with(&format!("[{} bytes omitted]", total - MAX_TEXT_BYTES)));
    let short = "CN=short";
    assert_eq!(cut_text(short), short);
    assert_eq!(cut_text(&"y".repeat(MAX_TEXT_BYTES)).len(), MAX_TEXT_BYTES);
    let wide = "\u{e9}".repeat(MAX_TEXT_BYTES);
    let cut = cut_text(&wide);
    assert!(cut.starts_with(&"\u{e9}".repeat(MAX_TEXT_BYTES / SMALL_CAP)));
    assert!(cut.contains(&format!("[{MAX_TEXT_BYTES} bytes omitted]")));
    let odd = format!("a{}", "\u{e9}".repeat(MAX_TEXT_BYTES));
    assert!(cut_text(&odd).contains(&format!("[{} bytes omitted]", odd.len() - (MAX_TEXT_BYTES - 1))));
    Ok(())
}


#[test]
fn batches_are_cut_at_the_batch_limit() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let records: Vec<CertRecord> = (1..=BATCHES_OF_2500).map(|index| cert(index, NOT_AFTER)).collect();
    let counts = run(store_records(&exec, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    assert_eq!(counts.inserted, BATCHES_OF_2500);
    let state = fake.state.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(
        state.statements,
        vec![MAX_STORE_BATCH, MAX_STORE_BATCH, BATCHES_OF_2500 - SMALL_CAP * MAX_STORE_BATCH]
    );
    Ok(())
}


#[test]
fn a_fingerprint_repeated_in_one_call_is_counted_and_the_counts_add_up() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    let mut twin = cert(1, NOT_AFTER);
    twin.subject = "CN=other".to_owned();
    let mut bad = cert(THREE, NOT_AFTER);
    bad.fingerprint_sha256 = "zz".to_owned();
    let records = vec![cert(1, NOT_AFTER), twin, cert(SMALL_CAP, NOT_AFTER), cert(1, NOT_AFTER), bad];
    let counts = run(store_records(&exec, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))??;
    assert_eq!(
        (counts.inserted, counts.duplicate_in_batch, counts.refused_record),
        (SMALL_CAP, SMALL_CAP, 1)
    );
    let sum = counts.inserted + counts.seen_again + counts.refused_full + counts.refused_source + counts.refused_record + counts.duplicate_in_batch;
    assert_eq!(sum, records.len());
    let state = fake.state.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(state.statements, vec![SMALL_CAP]);
    Ok(())
}


#[test]
fn a_failing_store_and_malformed_answers_are_errors() -> TestResult {
    let scope = tenant_scope("a")?;
    let records = vec![cert(1, NOT_AFTER)];
    let failing = Fake {
        fail: true,
        ..Fake::default()
    };
    let down = executor(&failing);
    assert!(matches!(
        run(store_records(&down, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))?,
        Err(InventoryStoreError::Pg(_))
    ));
    let empty = fixed(Vec::new());
    assert!(matches!(
        run(store_records(&empty, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))?,
        Err(InventoryStoreError::BadRow { column: 0 })
    ));
    let short = fixed(vec![vec!["1".to_owned()]]);
    assert!(matches!(
        run(store_records(&short, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))?,
        Err(InventoryStoreError::BadRow { column: 1 })
    ));
    let words = fixed(vec![vec!["1".to_owned(), "x".to_owned(), "0".to_owned()]]);
    assert!(matches!(
        run(store_records(&words, &scope, &scan_source(), &records, NOW, &DEFAULT_LIMITS))?,
        Err(InventoryStoreError::BadRow { column: 1 })
    ));
    Ok(())
}


#[test]
fn cursors_are_canonical() -> TestResult {
    let fingerprint = "a".repeat(HEX_WIDTH);
    assert_eq!(
        decode_cursor(&encode_cursor(NEGATIVE_TIME, &fingerprint))?,
        (NEGATIVE_TIME, fingerprint.clone())
    );
    assert_eq!(decode_cursor(&encode_cursor(i64::MAX, &fingerprint))?.0, i64::MAX);
    let bad = [
        String::new(),
        "nocolon".to_owned(),
        format!("x:{fingerprint}"),
        format!("+5:{fingerprint}"),
        format!("05:{fingerprint}"),
        format!("5:{}", "A".repeat(HEX_WIDTH)),
        "5:abc".to_owned(),
    ];
    bad.iter()
        .for_each(|text| assert!(matches!(decode_cursor(text), Err(InventoryStoreError::BadCursor)), "{text}"));
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope("a")?;
    assert!(matches!(
        run(list_certificates(&exec, &scope, &CertFilter::default(), Some("junk"), 1))?,
        Err(InventoryStoreError::BadCursor)
    ));
    assert!(matches!(
        run(list_certificates(&exec, &scope, &CertFilter::default(), None, 0))?,
        Err(InventoryStoreError::BadPageSize { .. })
    ));
    assert!(matches!(
        run(list_certificates(&exec, &scope, &CertFilter::default(), None, MAX_PAGE + 1))?,
        Err(InventoryStoreError::BadPageSize { .. })
    ));
    Ok(())
}


fn good_row() -> Vec<String> {
    let fingerprint = "a".repeat(HEX_WIDTH);
    [
        fingerprint.as_str(),
        "CN=a",
        "CN=ca",
        "[\"a.example.com\"]",
        "1",
        "2",
        "rsa",
        "2048",
        "false",
        "3",
        "4",
    ]
    .iter()
    .map(|text| (*text).to_owned())
    .collect()
}


fn with_column(column: usize, value: &str) -> Vec<String> {
    let mut row = good_row();
    row.iter_mut()
        .enumerate()
        .filter(|(index, _)| *index == column)
        .for_each(|(_, cell)| *cell = value.to_owned());
    row
}


#[test]
fn stored_rows_are_parsed_strictly() -> TestResult {
    let scope = tenant_scope("a")?;
    let page = run(list_certificates(&fixed(vec![good_row()]), &scope, &CertFilter::default(), None, 1))??;
    let stored = page.certs.first().ok_or("none")?;
    assert_eq!(
        (stored.record.key_bits, stored.record.key_type, stored.record.self_signed),
        (Some(KEY_BITS), KeyType::Rsa, false)
    );
    let ec = run(list_certificates(
        &fixed(vec![with_column(COL_KEY_TYPE, "ec")]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))??;
    assert_eq!(ec.certs.first().ok_or("none")?.record.key_type, KeyType::Ec);
    let no_bits = run(list_certificates(
        &fixed(vec![with_column(COL_KEY_BITS, "")]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))??;
    assert_eq!(no_bits.certs.first().ok_or("none")?.record.key_bits, None);
    let signed = run(list_certificates(
        &fixed(vec![with_column(COL_SELF_SIGNED, "true")]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))??;
    assert!(signed.certs.first().ok_or("none")?.record.self_signed);
    let other = run(list_certificates(
        &fixed(vec![with_column(COL_KEY_TYPE, "other")]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))??;
    assert_eq!(other.certs.first().ok_or("none")?.record.key_type, KeyType::Other);
    let broken = [
        (COL_DNS_NAMES, "not json"),
        (COL_NOT_BEFORE, "x"),
        (COL_NOT_AFTER, "x"),
        (COL_KEY_TYPE, "dsa"),
        (COL_KEY_BITS, "x"),
        (COL_SELF_SIGNED, "maybe"),
        (COL_FIRST_SEEN, "x"),
        (COL_LAST_SEEN, "x"),
    ];
    broken.iter().try_for_each(|(column, value)| -> TestResult {
        let result = run(list_certificates(
            &fixed(vec![with_column(*column, value)]),
            &scope,
            &CertFilter::default(),
            None,
            1,
        ))?;
        assert!(
            matches!(result, Err(InventoryStoreError::BadRow { column: found }) if found == *column),
            "{column}"
        );
        Ok(())
    })?;
    let short = run(list_certificates(
        &fixed(vec![vec!["a".to_owned()]]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))?;
    assert!(matches!(short, Err(InventoryStoreError::BadRow { column: COL_DNS_NAMES })));
    let paged = run(list_certificates(
        &fixed(vec![good_row(), good_row()]),
        &scope,
        &CertFilter::default(),
        None,
        1,
    ))??;
    assert_eq!(paged.certs.len(), 1);
    assert_eq!(paged.next_cursor, Some(format!("2:{}", "a".repeat(HEX_WIDTH))));
    Ok(())
}


#[test]
fn sightings_are_read_for_a_valid_fingerprint_only() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = Fake::default();
    let exec = executor(&fake);
    let record = cert(1, NOT_AFTER);
    run(store_records(
        &exec,
        &scope,
        &scan_source(),
        std::slice::from_ref(&record),
        NOW,
        &DEFAULT_LIMITS,
    ))??;
    run(store_records(
        &exec,
        &scope,
        &source(SourceKind::Ct, "ct.example.org"),
        std::slice::from_ref(&record),
        LATER,
        &DEFAULT_LIMITS,
    ))??;
    let found = run(sightings_of(&exec, &scope, &record.fingerprint_sha256))??;
    assert_eq!(
        found.iter().map(|sighting| sighting.kind).collect::<Vec<_>>(),
        vec![SourceKind::Ct, SourceKind::Scan]
    );
    let other = run(sightings_of(&exec, &tenant_scope("b")?, &record.fingerprint_sha256))??;
    assert!(other.is_empty());
    assert!(matches!(
        run(sightings_of(&exec, &scope, "zz"))?,
        Err(InventoryStoreError::BadFingerprint)
    ));
    let weird = fixed(vec![vec!["mail".to_owned(), "x".to_owned(), "1".to_owned()]]);
    assert!(matches!(
        run(sightings_of(&weird, &scope, &record.fingerprint_sha256))?,
        Err(InventoryStoreError::BadRow { column: 0 })
    ));
    Ok(())
}


#[test]
fn texts_and_migrations() -> TestResult {
    assert_eq!(kind_text(SourceKind::Scan), "scan");
    assert_eq!(kind_text(SourceKind::Ct), "ct");
    assert_eq!(key_type_text(KeyType::Rsa), "rsa");
    assert_eq!(key_type_text(KeyType::Ec), "ec");
    assert_eq!(key_type_text(KeyType::Other), "other");
    check_namespace(MIGRATION_NAMESPACE)?;
    check_embedded(&MIGRATIONS)?;
    let doc = doc_of(&cert(1, NOT_AFTER));
    assert_eq!(doc.get("key_bits"), Some(&serde_json::Value::Null));
    Ok(())
}
