use backup_monitor::error::BackupError;
use backup_monitor::model::{Limits, Listing, SkipReason};
use backup_monitor::parse::{parse_borg, parse_restic, reserve_exact};
use backup_monitor::text::{is_hidden, valid_id, valid_text};
use serde_json::{json, Value};
use std::error::Error;
use std::io::Read;
use time::macros::datetime;
use time::OffsetDateTime;


const ECHO_REPEATS: usize = 100;


const FIRST: u32 = 1;


const SECOND: u32 = 2;


const THIRD: u32 = 3;


const BORG_REPOSITORY: u32 = 99;


const WRONG_NUMBER: u32 = 5;


const EPOCH_SECONDS: u64 = 1_700_000_000;


const ID_LEN: usize = 64;


const HOST_MAX: usize = 253;


const LONG_HOST: usize = 300;


const NAME_MAX: usize = 255;


const TINY_BYTES: u64 = 2;


const HUGE_CAP: u64 = 16;


const TWO: usize = 2;


const TEXT_CAP: usize = 4;


const PATH_CAP: usize = 5;


const UTC_FROM_OFFSET: OffsetDateTime = datetime!(2026-11-12 09:00:00.123456789 UTC);


const BORG_TIME: OffsetDateTime = datetime!(2026-11-12 10:00:00.5 UTC);


const BORG_WHOLE_SECONDS: OffsetDateTime = datetime!(2026-11-12 10:00:07 UTC);


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected failure"))
    }
}


fn id(number: u32) -> String {
    format!("{number:064x}")
}


fn restic_item(number: u32) -> Value {
    json!({"id": id(number), "short_id": "abcdef12", "time": "2026-11-12T10:00:00.123456789+01:00", "hostname": "web1",
        "paths": ["/etc"], "tags": ["daily"]})
}


fn restic(value: &Value, limits: &Limits) -> Result<Listing, BackupError> {
    parse_restic(value.to_string().as_bytes(), "repo", limits)
}


fn borg(value: &Value, from_name: bool, limits: &Limits) -> Result<Listing, BackupError> {
    parse_borg(value.to_string().as_bytes(), from_name, limits)
}


fn set_field(mut item: Value, key: &str, value: Value) -> Value {
    item.as_object_mut().into_iter().for_each(|object| {
        object.insert(key.to_owned(), value.clone());
    });
    item
}


fn restic_with(key: &str, value: Value) -> Value {
    let item = set_field(restic_item(FIRST), key, value);
    json!([item])
}


fn skipped_once(listing: &Listing, reason: SkipReason) -> bool {
    listing.snapshots.is_empty() && listing.skipped.len() == 1 && listing.skipped.get(&reason) == Some(&1)
}


fn borg_item(number: u32, name: &str) -> Value {
    json!({"id": id(number), "name": name, "start": "2026-11-12T10:00:00.500000", "time": "2026-11-12T10:00:00.500000"})
}


fn borg_root(archives: Value) -> Value {
    json!({"repository": {"id": id(BORG_REPOSITORY), "location": "/srv/borg"}, "archives": archives})
}


fn borg_with(key: &str, value: Value) -> Value {
    let item = set_field(borg_item(FIRST, "web1-monday"), key, value);
    borg_root(json!([item]))
}


fn restic_minimal(extra: Value) -> Value {
    set_field(json!({"id": id(FIRST), "time": "2026-11-12T10:00:00Z", "hostname": "a"}), "extra", extra)
}


#[test]
fn restic_listing_is_parsed_to_utc() -> Result<(), Box<dyn Error>> {
    let listing = restic(&json!([restic_item(FIRST)]), &Limits::default())?;
    assert_eq!(listing.repository, "repo");
    let snapshot = listing.snapshots.first().ok_or("no snapshot")?;
    assert_eq!(snapshot.id, id(FIRST));
    assert_eq!(snapshot.host.as_deref(), Some("web1"));
    assert_eq!(snapshot.paths, vec!["/etc"]);
    assert_eq!(snapshot.tags, vec!["daily"]);
    assert_eq!(snapshot.time, UTC_FROM_OFFSET);
    assert!(listing.skipped.is_empty());
    Ok(())
}


#[test]
fn restic_absent_paths_and_tags_are_empty() -> Result<(), Box<dyn Error>> {
    let listing = restic(&json!([restic_minimal(json!(null))]), &Limits::default())?;
    let snapshot = listing.snapshots.first().ok_or("no snapshot")?;
    assert!(snapshot.paths.is_empty() && snapshot.tags.is_empty());
    Ok(())
}


#[test]
fn restic_byte_cap_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let at_limit = Limits {
        max_bytes: TINY_BYTES,
        ..Limits::default()
    };
    assert!(parse_restic(&b"[]"[..], "repo", &at_limit).is_ok());
    let below = Limits {
        max_bytes: TINY_BYTES - 1,
        ..Limits::default()
    };
    let refused = parse_restic(&b"[]"[..], "repo", &below);
    assert!(matches!(refused, Err(BackupError::TooLarge { limit }) if limit == TINY_BYTES - 1));
    Ok(())
}


#[test]
fn a_huge_listing_is_never_read_whole() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_bytes: HUGE_CAP,
        ..Limits::default()
    };
    let mut reader = std::io::repeat(b' ').take(u64::MAX);
    let result = parse_restic(&mut reader, "repo", &limits);
    assert!(matches!(result, Err(BackupError::TooLarge { .. })));
    assert_eq!(reader.limit(), u64::MAX - HUGE_CAP - 1);
    Ok(())
}


#[test]
fn unreadable_and_invalid_inputs_are_errors() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    assert!(matches!(parse_restic(FailingReader, "repo", &limits), Err(BackupError::Read(_))));
    assert!(matches!(parse_borg(FailingReader, false, &limits), Err(BackupError::Read(_))));
    assert!(matches!(parse_restic(&b"[1,"[..], "repo", &limits), Err(BackupError::Json(_))));
    assert!(matches!(parse_borg(&b"{"[..], false, &limits), Err(BackupError::Json(_))));
    Ok(())
}


#[test]
fn an_impossible_byte_limit_is_refused_before_reading() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_bytes: u64::MAX,
        ..Limits::default()
    };
    let mut reader = std::io::repeat(b' ').take(u64::MAX);
    let result = parse_restic(&mut reader, "repo", &limits);
    assert!(matches!(result, Err(BackupError::Reservation { .. })));
    assert_eq!(reader.limit(), u64::MAX);
    let refused = reserve_exact(u64::MAX).err().ok_or("reservation accepted")?;
    assert!(matches!(refused, BackupError::Reservation { .. }));
    assert!(refused.source().is_some());
    assert!(reserve_exact(HUGE_CAP)?.capacity() > HUGE_CAP as usize);
    Ok(())
}


#[test]
fn a_json_error_keeps_only_its_position() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let echoed = format!("{}\u{202e}", "secret".repeat(ECHO_REPEATS));
    let inputs = [format!("[\"{echoed}\" x"), format!("{{\"{echoed}\": }}"), format!("[\"{echoed}\"")];
    inputs.iter().try_for_each(|input| -> Result<(), Box<dyn Error>> {
        let error = parse_restic(input.as_bytes(), "repo", &limits).err().ok_or("accepted")?;
        let chain = format!("{error} {error:?} {:?}", error.source().map(ToString::to_string));
        assert!(matches!(error, BackupError::Json(_)));
        assert!(error.source().is_none());
        assert!(!chain.contains("secret") && !chain.contains('\u{202e}'), "{chain}");
        Ok(())
    })?;
    let wrong_type = format!("[{{\"id\": \"{echoed}\", \"paths\": \"{echoed}\"}}]");
    let listing = parse_restic(wrong_type.as_bytes(), "repo", &limits)?;
    assert_eq!(listing.snapshots.len(), 0);
    let error = parse_borg(&b"{\n\"repository\": }"[..], false, &limits).err().ok_or("accepted")?;
    assert_eq!(error.to_string(), "listing is not valid JSON: Syntax at line 2 column 15");
    Ok(())
}


#[test]
fn restic_snapshot_cap_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_snapshots: TWO,
        ..Limits::default()
    };
    let listing = restic(&json!([restic_item(FIRST), restic_item(SECOND)]), &limits)?;
    assert_eq!(listing.snapshots.len(), TWO);
    let over = restic(&json!([restic_item(FIRST), restic_item(SECOND), restic_item(THIRD)]), &limits);
    assert!(matches!(over, Err(BackupError::TooManySnapshots { limit }) if limit == TWO));
    Ok(())
}


#[test]
fn restic_wrong_typed_containers_refuse_the_listing() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    assert!(matches!(restic(&json!({"snapshots": []}), &limits), Err(BackupError::Malformed { .. })));
    assert!(matches!(
        restic(&json!([restic_item(FIRST), WRONG_NUMBER]), &limits),
        Err(BackupError::Malformed { .. })
    ));
    assert!(matches!(restic(&json!(null), &limits), Err(BackupError::Malformed { .. })));
    Ok(())
}


#[test]
fn restic_repository_name_is_checked() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let body = json!([restic_item(FIRST)]).to_string();
    assert!(matches!(parse_restic(body.as_bytes(), "-x", &limits), Err(BackupError::Malformed { .. })));
    assert!(matches!(parse_restic(body.as_bytes(), "", &limits), Err(BackupError::Malformed { .. })));
    Ok(())
}


#[test]
fn restic_wrong_typed_fields_skip_with_a_reason() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let cases = [
        ("id", json!(WRONG_NUMBER), SkipReason::BadId),
        ("id", json!("abc"), SkipReason::BadId),
        ("id", json!("A".repeat(ID_LEN)), SkipReason::BadId),
        ("time", json!(EPOCH_SECONDS), SkipReason::BadTime),
        ("time", json!("yesterday"), SkipReason::BadTime),
        ("hostname", json!(null), SkipReason::BadHost),
        ("hostname", json!(""), SkipReason::BadHost),
        ("hostname", json!("-web"), SkipReason::BadHost),
        ("hostname", json!("web\u{202e}1"), SkipReason::BadHost),
        ("hostname", json!("web\u{200b}1"), SkipReason::BadHost),
        ("hostname", json!("web\n1"), SkipReason::BadHost),
        ("hostname", json!("a".repeat(HOST_MAX + 1)), SkipReason::BadHost),
        ("hostname", json!("a".repeat(LONG_HOST)), SkipReason::BadHost),
        ("paths", json!({"a": FIRST}), SkipReason::BadPaths),
        ("paths", json!([WRONG_NUMBER]), SkipReason::BadPaths),
        ("paths", json!(null), SkipReason::BadPaths),
        ("tags", json!("daily"), SkipReason::BadTags),
        ("tags", json!(["-x"]), SkipReason::BadTags),
        ("tags", json!(["a\u{202e}"]), SkipReason::BadTags),
        ("tags", json!([""]), SkipReason::BadTags),
    ];
    cases.into_iter().try_for_each(|(key, value, reason)| {
        let listing = restic(&restic_with(key, value.clone()), &limits)?;
        assert!(skipped_once(&listing, reason), "{key} {value}");
        Ok::<(), BackupError>(())
    })?;
    Ok(())
}


#[test]
fn restic_text_and_list_caps_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_paths: TWO,
        max_tags: TWO,
        max_text_chars: TEXT_CAP,
        max_path_bytes: PATH_CAP,
        ..Limits::default()
    };
    let item =
        |key: &str, value: Value, host: &str| set_field(json!({"id": id(FIRST), "time": "2026-11-12T10:00:00Z", "hostname": host}), key, value);
    let accepted = json!([set_field(item("paths", json!(["12345", "1"]), "abcd"), "tags", json!(["abcd", "b"]))]);
    assert_eq!(restic(&accepted, &limits)?.snapshots.len(), 1);
    let cases = [
        (item("extra", json!(null), "abcde"), SkipReason::BadHost),
        (item("paths", json!(["123456"]), "a"), SkipReason::BadPaths),
        (item("paths", json!(["a", "b", "c"]), "a"), SkipReason::BadPaths),
        (item("tags", json!(["a", "b", "c"]), "a"), SkipReason::BadTags),
        (item("tags", json!(["abcde"]), "a"), SkipReason::BadTags),
    ];
    cases.into_iter().try_for_each(|(body, reason)| {
        assert!(skipped_once(&restic(&json!([body]), &limits)?, reason));
        Ok::<(), BackupError>(())
    })?;
    Ok(())
}


#[test]
fn restic_host_at_253_characters_is_accepted() -> Result<(), Box<dyn Error>> {
    let listing = restic(&restic_with("hostname", json!("a".repeat(HOST_MAX))), &Limits::default())?;
    assert_eq!(listing.snapshots.len(), 1);
    Ok(())
}


#[test]
fn a_repeated_id_is_skipped_as_duplicate() -> Result<(), Box<dyn Error>> {
    let items = json!([restic_item(FIRST), restic_item(FIRST), restic_item(SECOND)]);
    let listing = restic(&items, &Limits::default())?;
    assert_eq!(listing.snapshots.len(), TWO);
    assert_eq!(listing.skipped.get(&SkipReason::Duplicate), Some(&1));
    Ok(())
}


#[test]
fn borg_listing_reads_naive_time_as_utc() -> Result<(), Box<dyn Error>> {
    let listing = borg(&borg_root(json!([borg_item(FIRST, "web1-monday")])), true, &Limits::default())?;
    assert_eq!(listing.repository, id(BORG_REPOSITORY));
    let snapshot = listing.snapshots.first().ok_or("no snapshot")?;
    assert_eq!(snapshot.host.as_deref(), Some("web1"));
    assert_eq!(snapshot.time, BORG_TIME);
    assert!(snapshot.paths.is_empty() && snapshot.tags.is_empty());
    Ok(())
}


#[test]
fn borg_host_is_unknown_unless_the_file_asks() -> Result<(), Box<dyn Error>> {
    let listing = borg(&borg_root(json!([borg_item(FIRST, "nodash")])), false, &Limits::default())?;
    assert_eq!(listing.snapshots.first().ok_or("no snapshot")?.host, None);
    Ok(())
}


#[test]
fn borg_time_falls_back_to_the_time_field_and_accepts_whole_seconds() -> Result<(), Box<dyn Error>> {
    let item = json!({"id": id(FIRST), "name": "web1-a", "time": "2026-11-12T10:00:07"});
    let listing = borg(&borg_root(json!([item])), true, &Limits::default())?;
    assert_eq!(listing.snapshots.first().ok_or("no snapshot")?.time, BORG_WHOLE_SECONDS);
    Ok(())
}


#[test]
fn borg_wrong_typed_containers_refuse_the_listing() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let root = "listing is not an object";
    let repository = "repository id";
    let archives = "archives is not an array";
    let rows = [
        (json!([]), root),
        (json!([{"id": id(FIRST)}, [borg_item(FIRST, "host-a")]]), root),
        (json!(["x", []]), root),
        (json!(WRONG_NUMBER), root),
        (json!([[id(FIRST)], [borg_item(FIRST, "host-a")]]), root),
        (json!({"archives": []}), repository),
        (json!({"repository": WRONG_NUMBER, "archives": []}), repository),
        (json!({"repository": {"id": "short"}, "archives": []}), repository),
        (json!({"repository": [id(FIRST)], "archives": []}), repository),
        (json!({"repository": [{"id": id(FIRST)}], "archives": []}), repository),
        (json!({"repository": {"id": id(FIRST)}}), archives),
        (json!({"repository": {"id": id(FIRST)}, "archives": {}}), archives),
        (borg_root(json!(["x"])), "snapshot is not an object"),
    ];
    rows.iter().for_each(|(body, what)| {
        let result = borg(body, true, &limits);
        assert!(
            matches!(&result, Err(BackupError::Malformed { what: found }) if found == what),
            "{body}: {result:?}"
        );
    });
    Ok(())
}


#[test]
fn borg_snapshot_cap_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_snapshots: 1,
        ..Limits::default()
    };
    assert_eq!(borg(&borg_root(json!([borg_item(FIRST, "a-b")])), true, &limits)?.snapshots.len(), 1);
    let over = borg(&borg_root(json!([borg_item(FIRST, "a-b"), borg_item(SECOND, "a-c")])), true, &limits);
    assert!(matches!(over, Err(BackupError::TooManySnapshots { limit: 1 })));
    Ok(())
}


#[test]
fn borg_wrong_typed_fields_skip_with_a_reason() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    let cases = [
        ("id", json!(FIRST), SkipReason::BadId),
        ("start", json!(WRONG_NUMBER), SkipReason::BadTime),
        ("start", json!("2026-11-12 10:00:00"), SkipReason::BadTime),
        ("name", json!(WRONG_NUMBER), SkipReason::BadName),
        ("name", json!("web1\u{202e}-x"), SkipReason::BadName),
        ("name", json!("a".repeat(NAME_MAX + 1)), SkipReason::BadName),
        ("name", json!("nodash"), SkipReason::BadHost),
        ("name", json!("-x-y"), SkipReason::BadHost),
        ("name", json!("web\u{200b}-y"), SkipReason::BadName),
    ];
    cases.into_iter().try_for_each(|(key, value, reason)| {
        let listing = borg(&borg_with(key, value.clone()), true, &limits)?;
        assert!(skipped_once(&listing, reason), "{key} {value}");
        Ok::<(), BackupError>(())
    })?;
    Ok(())
}


#[test]
fn borg_host_of_253_characters_and_duplicates() -> Result<(), Box<dyn Error>> {
    let name = format!("{}-y", "a".repeat(HOST_MAX));
    let item = borg_item(FIRST, &name);
    let listing = borg(&borg_root(json!([item.clone(), item])), true, &Limits::default())?;
    assert_eq!(listing.snapshots.len(), 1);
    assert_eq!(listing.skipped.get(&SkipReason::Duplicate), Some(&1));
    Ok(())
}


#[test]
fn borg_name_cap_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_name_chars: TEXT_CAP,
        ..Limits::default()
    };
    assert_eq!(borg(&borg_root(json!([borg_item(FIRST, "ab-c")])), true, &limits)?.snapshots.len(), 1);
    let over = borg(&borg_root(json!([borg_item(FIRST, "ab-cd")])), true, &limits)?;
    assert!(skipped_once(&over, SkipReason::BadName));
    Ok(())
}


#[test]
fn text_grammar_helpers() -> Result<(), Box<dyn Error>> {
    assert!(is_hidden('\u{202e}') && is_hidden('\u{200b}') && is_hidden('\u{2028}') && is_hidden('\u{0}'));
    assert!(!is_hidden('a'));
    assert!(valid_text("web-1", PATH_CAP) && !valid_text("web-12", PATH_CAP) && !valid_text("", PATH_CAP) && !valid_text("-a", PATH_CAP));
    assert!(valid_id(&id(BORG_REPOSITORY)) && !valid_id("zz") && !valid_id(&"G".repeat(ID_LEN)));
    Ok(())
}


#[test]
fn a_repeated_key_refuses_the_listing_and_escapes_are_decoded() -> Result<(), Box<dyn Error>> {
    let repeated = format!("[{{\"id\":\"{}\",\"id\":\"{}\"}}]", id(FIRST), id(SECOND));
    let refused = parse_restic(repeated.as_bytes(), "repo", &Limits::default());
    assert!(matches!(refused, Err(BackupError::Malformed { .. })));
    let escaped = format!(
        "[{{\"id\":\"{}\",\"time\":\"2026-11-12T10:00:00Z\",\"hostname\":\"w\\u0065b\"}}]",
        id(FIRST)
    );
    let listing = parse_restic(escaped.as_bytes(), "repo", &Limits::default())?;
    assert_eq!(listing.snapshots.first().and_then(|snapshot| snapshot.host.as_deref()), Some("web"));
    Ok(())
}


#[test]
fn a_time_outside_the_utc_range_is_skipped_not_a_panic() -> Result<(), Box<dyn Error>> {
    let restic_listing = restic(&restic_with("time", json!("9999-12-31T23:00:00-02:00")), &Limits::default())?;
    assert!(skipped_once(&restic_listing, SkipReason::BadTime));
    let borg_listing = borg(&borg_with("start", json!("9999-12-31T23:00:00-02:00")), true, &Limits::default())?;
    assert!(skipped_once(&borg_listing, SkipReason::BadTime));
    Ok(())
}
