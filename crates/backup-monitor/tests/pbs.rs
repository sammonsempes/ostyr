use backup_monitor::coverage::{coverage, unverified_count};
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::BackupError;
use backup_monitor::model::{CoverageStatus, Limits, Listing, SkipReason, Verification};
use backup_monitor::parse::{parse_pbs, parse_restic};
use backup_monitor::text::{display_text, valid_host_key, valid_text};
use serde_json::{json, Value};
use std::error::Error;
use time::macros::datetime;
use time::OffsetDateTime;


const DECLARATIONS: &str = "tenant: lab\ncritical:\n  - host: vm/9001\n    max_age_hours: 24\n  - host: host/web\n    max_age_hours: 24\n  - host: srv1\n    max_age_hours: 24\n";


const BACKUP_TIME: i64 = 1_794_000_000;


const LAB_DECLARATIONS: &str =
    "tenant: lab\ncritical:\n  - host: vm/9001\n    max_age_hours: 24\n  - host: ct/9003\n    max_age_hours: 24\n  - host: host/pve\n    max_age_hours: 24\n";


const LAB_UNVERIFIED: &str = include_str!("fixtures/pbs-lab-unverified.json");


const LAB_FAILED: &str = include_str!("fixtures/pbs-lab-failed.json");


const LAB_NOW: OffsetDateTime = datetime!(2026-11-14 12:00 UTC);


const LAB_SNAPSHOTS: usize = 4;


const LAB_HOSTS: usize = 3;


const NOW: OffsetDateTime = datetime!(2026-11-07 00:00 UTC);


const YEAR_10000: i64 = 253_402_300_800;


const NEGATIVE_YEAR: i64 = -62_167_219_201;


const PATH_CAP: usize = 3;


const OWNER_CHARS: usize = 10_000;


const OWNER_SHOWN: usize = 128;


const HOST_MAX: usize = 253;


const SIZE: u64 = 1024;


const NEWER_SECONDS: i64 = 60;


const PAIR: usize = 2;


const FOUR: usize = 4;


const SRV1_INDEX: usize = 2;


const NOT_TEXT: u32 = 5;


fn item(kind: &str, name: &str) -> Value {
    json!({"backup-type": kind, "backup-id": name, "backup-time": BACKUP_TIME, "owner": "root@pam", "protected": false,
        "size": SIZE, "files": [{"filename": "a.pxar.didx"}], "verification": {"state": "ok", "upid": "UPID:x"}})
}


fn with(mut value: Value, key: &str, new: Value) -> Value {
    value.as_object_mut().into_iter().for_each(|object| {
        object.insert(key.to_owned(), new.clone());
    });
    value
}


fn without(mut value: Value, key: &str) -> Value {
    value.as_object_mut().into_iter().for_each(|object| {
        object.remove(key);
    });
    value
}


fn pbs(value: &Value) -> Result<Listing, BackupError> {
    parse_pbs(value.to_string().as_bytes(), "store1", &Limits::default())
}


fn refused_as(value: Value, reason: SkipReason) -> Result<bool, Box<dyn Error>> {
    let listing = pbs(&json!([value]))?;
    Ok(listing.snapshots.is_empty() && listing.skipped.get(&reason) == Some(&1))
}


fn statuses(listing: Listing) -> Result<Vec<CoverageStatus>, Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    Ok(coverage(&[listing], &declarations, NOW).into_iter().map(|entry| entry.status).collect())
}


#[test]
fn a_guest_snapshot_is_keyed_type_slash_id_and_covers_it() -> Result<(), Box<dyn Error>> {
    let listing = pbs(&json!([item("vm", "9001")]))?;
    let snapshot = listing.snapshots.first().ok_or("none")?;
    assert_eq!(snapshot.host.as_deref(), Some("vm/9001"));
    assert_eq!(snapshot.time.unix_timestamp(), BACKUP_TIME);
    let detail = snapshot.pbs.as_ref().ok_or("no detail")?;
    assert_eq!(
        (detail.owner.as_deref(), detail.protected, detail.size, detail.files),
        (Some("root@pam"), false, Some(SIZE), 1)
    );
    assert_eq!(detail.verification, Verification::Verified);
    assert_eq!(statuses(listing)?.first(), Some(&CoverageStatus::Ok));
    Ok(())
}


#[test]
fn a_failed_verification_does_not_cover_and_an_absent_one_covers_and_is_counted() -> Result<(), Box<dyn Error>> {
    let failed = with(item("vm", "9001"), "verification", json!({"state": "failed"}));
    let failed_listing = pbs(&json!([failed]))?;
    assert_eq!(failed_listing.snapshots.len(), 1);
    assert_eq!(statuses(failed_listing)?.first(), Some(&CoverageStatus::Missing));
    let absent = pbs(&json!([without(item("vm", "9001"), "verification")]))?;
    assert_eq!(unverified_count(&absent), 1);
    assert_eq!(statuses(absent)?.first(), Some(&CoverageStatus::Ok));
    let stateless = pbs(&json!([with(item("vm", "9001"), "verification", json!({}))]))?;
    assert_eq!(unverified_count(&stateless), 1);
    let verified = pbs(&json!([item("vm", "9001")]))?;
    assert_eq!(unverified_count(&verified), 0);
    Ok(())
}


#[test]
fn an_older_good_snapshot_still_covers_when_the_newest_failed() -> Result<(), Box<dyn Error>> {
    let newest = with(
        with(item("vm", "9001"), "verification", json!({"state": "failed"})),
        "backup-time",
        json!(BACKUP_TIME + NEWER_SECONDS),
    );
    let listing = pbs(&json!([newest, item("vm", "9001")]))?;
    assert_eq!(listing.snapshots.len(), PAIR);
    let report = coverage(&[listing], &load_declarations(DECLARATIONS, "d.yaml")?, NOW);
    assert_eq!(
        report.first().ok_or("none")?.newest.map(OffsetDateTime::unix_timestamp),
        Some(BACKUP_TIME)
    );
    Ok(())
}


#[test]
fn a_restic_listing_has_no_pbs_detail_and_counts_no_unverified() -> Result<(), Box<dyn Error>> {
    let listing = parse_restic(
        json!([{"id": format!("{:064x}", 1), "time": "2026-11-06T22:00:00Z", "hostname": "srv1"}])
            .to_string()
            .as_bytes(),
        "repo",
        &Limits::default(),
    )?;
    assert!(listing.snapshots.first().ok_or("none")?.pbs.is_none());
    assert_eq!(unverified_count(&listing), 0);
    assert_eq!(statuses(listing)?.get(SRV1_INDEX), Some(&CoverageStatus::Ok));
    Ok(())
}


#[test]
fn each_refused_value_is_a_counted_skip() -> Result<(), Box<dyn Error>> {
    assert!(refused_as(item("lxc", "1"), SkipReason::BadHost)?);
    assert!(refused_as(with(item("vm", "1"), "backup-type", json!(1)), SkipReason::BadHost)?);
    assert!(refused_as(without(item("vm", "1"), "backup-type"), SkipReason::BadHost)?);
    assert!(refused_as(item("vm", "web\u{3164}"), SkipReason::BadHost)?);
    assert!(refused_as(item("vm", "-web"), SkipReason::BadHost)?);
    assert!(refused_as(item("vm", ".web"), SkipReason::BadHost)?);
    assert!(refused_as(item("vm", "a/b"), SkipReason::BadHost)?);
    assert!(refused_as(item("vm", &"a".repeat(HOST_MAX)), SkipReason::BadHost)?);
    assert!(refused_as(with(item("vm", "1"), "backup-time", json!(YEAR_10000)), SkipReason::BadTime)?);
    assert!(refused_as(
        with(item("vm", "1"), "backup-time", json!(NEGATIVE_YEAR)),
        SkipReason::BadTime
    )?);
    assert!(refused_as(with(item("vm", "1"), "backup-time", json!(i64::MAX)), SkipReason::BadTime)?);
    assert!(refused_as(with(item("vm", "1"), "backup-time", json!("x")), SkipReason::BadTime)?);
    assert!(refused_as(without(item("vm", "1"), "backup-time"), SkipReason::BadTime)?);
    assert!(refused_as(with(item("vm", "1"), "protected", json!(null)), SkipReason::BadField)?);
    assert!(refused_as(with(item("vm", "1"), "size", json!("big")), SkipReason::BadField)?);
    assert!(refused_as(with(item("vm", "1"), "verification", json!("ok")), SkipReason::BadField)?);
    assert!(refused_as(
        with(item("vm", "1"), "verification", json!({"state": "maybe"})),
        SkipReason::BadField
    )?);
    assert!(refused_as(with(item("vm", "1"), "files", json!({})), SkipReason::BadPaths)?);
    Ok(())
}


#[test]
fn the_last_valid_year_and_optional_fields_are_accepted() -> Result<(), Box<dyn Error>> {
    let last = with(item("host", "web"), "backup-time", json!(YEAR_10000 - 1));
    let sparse = without(without(without(item("ct", "100"), "owner"), "size"), "protected");
    let listing = pbs(&json!([
        last,
        sparse,
        with(item("ct", "101"), "owner", json!(NOT_TEXT)),
        without(item("ct", "102"), "files")
    ]))?;
    assert_eq!(listing.snapshots.len(), FOUR);
    let detail = listing.snapshots.get(1).and_then(|snapshot| snapshot.pbs.as_ref()).ok_or("none")?;
    assert_eq!((detail.owner.clone(), detail.size, detail.protected), (None, None, false));
    assert_eq!(
        listing
            .snapshots
            .get(PAIR)
            .and_then(|snapshot| snapshot.pbs.as_ref())
            .ok_or("none")?
            .owner,
        None
    );
    assert_eq!(
        listing
            .snapshots
            .get(FOUR - 1)
            .and_then(|snapshot| snapshot.pbs.as_ref())
            .ok_or("none")?
            .files,
        0
    );
    Ok(())
}


#[test]
fn files_at_the_cap_are_counted_and_one_more_is_refused() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_paths: PATH_CAP,
        ..Limits::default()
    };
    let at_cap = with(item("vm", "1"), "files", json!([0, 0, 0]));
    let over = with(item("vm", "2"), "files", json!([0, 0, 0, 0]));
    let listing = parse_pbs(json!([at_cap, over]).to_string().as_bytes(), "store1", &limits)?;
    assert_eq!(listing.snapshots.len(), 1);
    assert_eq!(
        listing
            .snapshots
            .first()
            .and_then(|snapshot| snapshot.pbs.as_ref())
            .map(|detail| detail.files),
        Some(PATH_CAP)
    );
    assert_eq!(listing.skipped.get(&SkipReason::BadPaths), Some(&1));
    Ok(())
}


#[test]
fn a_repeated_snapshot_is_a_duplicate() -> Result<(), Box<dyn Error>> {
    let listing = pbs(&json!([item("vm", "1"), item("vm", "1")]))?;
    assert_eq!((listing.snapshots.len(), listing.skipped.get(&SkipReason::Duplicate)), (1, Some(&1)));
    Ok(())
}


#[test]
fn a_root_object_is_malformed_and_a_bad_repository_name_is_refused() -> Result<(), Box<dyn Error>> {
    assert!(matches!(pbs(&json!({"data": []})), Err(BackupError::Malformed { .. })));
    assert!(matches!(
        parse_pbs(b"[]".as_slice(), "-repo", &Limits::default()),
        Err(BackupError::Malformed { what: "repository name" })
    ));
    assert!(parse_pbs(b"[]".as_slice(), "store1", &Limits::default()).is_ok());
    assert!(matches!(pbs(&json!([item("vm", "1"), NOT_TEXT])), Err(BackupError::Malformed { .. })));
    Ok(())
}


#[test]
fn the_ascii_grammar_refuses_look_alikes_and_leading_dots() -> Result<(), Box<dyn Error>> {
    assert!(valid_text("srv1", HOST_MAX) && valid_text("a.b_c-d", HOST_MAX) && valid_text("_x", HOST_MAX));
    assert!(!valid_text("srv1\u{3164}", HOST_MAX) && !valid_text("srv\u{e9}", HOST_MAX) && !valid_text(".a", HOST_MAX));
    assert!(!valid_text("a b", HOST_MAX) && !valid_text("-a", HOST_MAX) && !valid_text("", HOST_MAX));
    assert!(valid_text(&"a".repeat(HOST_MAX), HOST_MAX) && !valid_text(&"a".repeat(HOST_MAX + 1), HOST_MAX));
    Ok(())
}


#[test]
fn a_declared_host_key_allows_one_slash_between_two_valid_parts() -> Result<(), Box<dyn Error>> {
    assert!(valid_host_key("vm/9001", HOST_MAX) && valid_host_key("srv1", HOST_MAX));
    assert!(!valid_host_key("vm/a/b", HOST_MAX) && !valid_host_key("vm/", HOST_MAX) && !valid_host_key("/a", HOST_MAX));
    assert!(!valid_host_key("vm/-a", HOST_MAX) && !valid_host_key("vm/a\u{3164}", HOST_MAX) && !valid_host_key("ab/c", PATH_CAP));
    Ok(())
}


#[test]
fn a_look_alike_restic_host_is_refused_and_does_not_cover_the_real_one() -> Result<(), Box<dyn Error>> {
    let element = json!({"id": format!("{:064x}", 1), "time": "2026-11-06T22:00:00Z", "hostname": "srv1\u{3164}"});
    let listing = parse_restic(json!([element]).to_string().as_bytes(), "repo", &Limits::default())?;
    assert_eq!(listing.skipped.get(&SkipReason::BadHost), Some(&1));
    assert_eq!(statuses(listing)?.get(SRV1_INDEX), Some(&CoverageStatus::Missing));
    Ok(())
}


#[test]
fn a_long_owner_with_a_newline_is_cut_and_escaped_and_never_fails_the_listing() -> Result<(), Box<dyn Error>> {
    let owner = format!("a\n{}", "b".repeat(OWNER_CHARS));
    let listing = pbs(&json!([with(item("vm", "1"), "owner", json!(owner))]))?;
    let shown = listing
        .snapshots
        .first()
        .and_then(|snapshot| snapshot.pbs.as_ref())
        .and_then(|detail| detail.owner.clone())
        .ok_or("none")?;
    assert!(shown.starts_with("a\\n") && shown.ends_with("...") && !shown.contains('\n'));
    assert_eq!(shown.len(), OWNER_SHOWN + 1 + "...".len());
    assert_eq!(display_text("ok\u{202e}", OWNER_SHOWN), "ok\\u{202e}");
    assert_eq!(display_text("abc", PATH_CAP), "abc");
    assert_eq!(display_text("abcd", PATH_CAP), "abc...");
    Ok(())
}


#[test]
fn the_live_listing_covers_the_declared_guests_and_counts_the_unverified_one() -> Result<(), Box<dyn Error>> {
    let listing = parse_pbs(LAB_UNVERIFIED.as_bytes(), "store1", &Limits::default())?;
    assert_eq!(
        (listing.snapshots.len(), listing.skipped.len(), unverified_count(&listing)),
        (LAB_SNAPSHOTS, 0, 1)
    );
    let report = coverage(&[listing], &load_declarations(LAB_DECLARATIONS, "d.yaml")?, LAB_NOW);
    assert!(report.iter().all(|entry| entry.status == CoverageStatus::Ok));
    assert_eq!(report.len(), LAB_HOSTS);
    Ok(())
}


#[test]
fn the_live_listing_after_a_corrupted_chunk_leaves_the_container_uncovered() -> Result<(), Box<dyn Error>> {
    let listing = parse_pbs(LAB_FAILED.as_bytes(), "store1", &Limits::default())?;
    assert_eq!((listing.snapshots.len(), unverified_count(&listing)), (LAB_SNAPSHOTS, 0));
    let statuses: Vec<(String, CoverageStatus)> = coverage(&[listing], &load_declarations(LAB_DECLARATIONS, "d.yaml")?, LAB_NOW)
        .into_iter()
        .map(|entry| (entry.host, entry.status))
        .collect();
    assert_eq!(
        statuses,
        vec![
            ("vm/9001".to_owned(), CoverageStatus::Ok),
            ("ct/9003".to_owned(), CoverageStatus::Missing),
            ("host/pve".to_owned(), CoverageStatus::Ok)
        ]
    );
    Ok(())
}
