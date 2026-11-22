use ad_posture::checks::SECONDS_PER_DAY;
use ad_posture::error::{IndicatorError, SnapshotError};
use ad_posture::indicator::{
    captured_of, checked_now, indicator_json, indicator_of, reason_of, source_of, warning_line, INDICATOR_INACTIVE_DAYS, INDICATOR_NAME,
    MAX_CLOCK_SKEW_SECONDS,
};
use ad_posture::limits::Limits;
use ad_posture::model::{Entry, Gap, IndicatorCounts, IndicatorOutcome, IndicatorRow, Refusal, Snapshot, Unreadable};
use ad_posture::snapshot::{read_captured, read_snapshot};
use ad_posture::thresholds::load_thresholds;
use std::error::Error;


const NOW: i64 = 1_700_000_000;


const CAPTURED: i64 = 1_699_996_400;


const CAPTURED_TEXT: &str = "2023-11-14T21:13:20Z";


const CAPTURED_OFFSET_TEXT: &str = "2023-11-14T23:13:20+02:00";


const HOUR: i64 = 3_600;


const DAYS: i64 = SECONDS_PER_DAY;


const FORTY_FIVE: i64 = 45;


const FORTY_SIX: i64 = 46;


const FORTY_FOUR: i64 = 44;


const FORTY: i64 = 40;


const FORTY_EIGHT: i64 = 48;


const MINUTE: i64 = 60;


const UAC_NORMAL: u32 = 512;


const UAC_DISABLED: u32 = 514;


const UAC_WORKSTATION: u32 = 4096;


const DOMAIN_SID: &str = "S-1-5-21-1-2-3";


const ADMIN_SID: &str = "S-1-5-21-1-2-3-500";


const OTHER_ADMIN_SID: &str = "S-1-5-21-9-9-9-500";


const OTHER_DOMAIN_SID: &str = "S-1-5-21-9-9-9";


const ADMINS_GROUP_SID: &str = "S-1-5-21-1-2-3-512";


const TENANT: &str = "t1";


const TICKS_PER_SECOND: i64 = 10_000_000;


const FILETIME_EPOCH_SECONDS: i64 = 11_644_473_600;


const YEAR_9999_UNIX: i64 = 253_402_214_400;


const MAX_ENTRIES: usize = 100_000;


const MAX_NOW: i64 = 9_999_999_999;


const MAX_SOURCE_LENGTH: usize = 200;


const TEN_KIB: usize = 10_240;


const ESC_NAME: &str = "evil\\u001bname";


const SKEW_BELOW: i64 = 299;


const SKEW_ABOVE: i64 = 301;


const FIVE: usize = 5;


const THREE: usize = 3;


const FOUR: usize = 4;


const TWO: usize = 2;


const THRESHOLDS_BIG: &str = "inactive_days: 36500\n";


fn entry(dn: &str, classes: &[&str], uac: u32, last_logon: Option<i64>, sid: Option<&str>) -> Entry {
    Entry {
        dn: dn.to_owned(),
        classes: classes.iter().map(|class| (*class).to_owned()).collect(),
        account: None,
        uac,
        spns: Vec::new(),
        member_of: Vec::new(),
        pwd_last_set: None,
        last_logon,
        sid: sid.map(str::to_owned),
        gaps: Vec::new(),
    }
}


fn user(dn: &str, last_logon: Option<i64>) -> Entry {
    entry(dn, &["top", "person", "user"], UAC_NORMAL, last_logon, None)
}


fn domain_entry() -> Entry {
    entry("DC=lab,DC=test", &["top", "domain", "domainDNS"], 0, None, Some(DOMAIN_SID))
}


fn administrator() -> Entry {
    entry(
        "CN=Administrator",
        &["top", "person", "user"],
        UAC_NORMAL,
        Some(CAPTURED),
        Some(ADMIN_SID),
    )
}


fn base() -> Vec<Entry> {
    vec![domain_entry(), administrator()]
}


fn snapshot_of(entries: Vec<Entry>) -> Snapshot {
    Snapshot {
        entries,
        ..Snapshot::default()
    }
}


fn row_of(outcome: IndicatorOutcome) -> Result<IndicatorRow, Box<dyn Error>> {
    match outcome {
        IndicatorOutcome::Row(row) => Ok(row),
        IndicatorOutcome::Refused { refusal, .. } => Err(format!("refused: {refusal:?}").into()),
    }
}


fn refusal_of(snapshot: &Snapshot, captured: Option<&str>) -> Result<Refusal, Box<dyn Error>> {
    match indicator_of(snapshot, captured, NOW, TENANT)? {
        IndicatorOutcome::Refused { refusal, .. } => Ok(refusal),
        IndicatorOutcome::Row(_) => Err("a row was emitted".into()),
    }
}


fn row_for(entries: Vec<Entry>) -> Result<IndicatorRow, Box<dyn Error>> {
    row_of(indicator_of(&snapshot_of(entries), Some(CAPTURED_TEXT), NOW, TENANT)?)
}


fn with(extra: Vec<Entry>) -> Vec<Entry> {
    let mut entries = base();
    entries.extend(extra);
    entries
}


fn filetime_of(unix: i64) -> i64 {
    (unix + FILETIME_EPOCH_SECONDS) * TICKS_PER_SECOND
}


#[test]
fn a_domain_with_only_a_fresh_administrator_is_zero() -> Result<(), Box<dyn Error>> {
    let row = row_for(base())?;
    assert_eq!(row.value, 0);
    assert_eq!(row.name, INDICATOR_NAME);
    assert_eq!(row.tenant, TENANT);
    assert_eq!(row.observed_at, CAPTURED_TEXT);
    assert_eq!(
        row.source,
        "ad:computed=1700000000;entries=2;accounts=1;inactive=0;never_logged=0;future=0;unreadable=0;inactive_days=45"
    );
    Ok(())
}


#[test]
fn every_kind_of_account_is_counted_as_stated() -> Result<(), Box<dyn Error>> {
    let computer = entry("CN=pc", &["top", "person", "user", "computer"], UAC_WORKSTATION, None, None);
    let group = entry("CN=grp", &["top", "group"], 0, None, None);
    let disabled = entry("CN=off", &["user"], UAC_DISABLED, None, None);
    let never = user("CN=never", None);
    let stale = user("CN=stale", Some(CAPTURED - FORTY_SIX * DAYS));
    let fresh = user("CN=fresh", Some(CAPTURED - FORTY_FOUR * DAYS));
    let row = row_for(with(vec![computer, group, disabled, never, stale, fresh]))?;
    assert_eq!(row.value, TWO);
    assert!(row
        .source
        .contains("entries=8;accounts=4;inactive=2;never_logged=1;future=0;unreadable=0;"));
    Ok(())
}


#[test]
fn a_zero_filetime_counts_as_never_through_the_reader() -> Result<(), Box<dyn Error>> {
    let text = format!(
        "{{\"captured\":\"{CAPTURED_TEXT}\",\"entries\":[\
        {{\"distinguishedName\":\"DC=x\",\"objectClass\":[\"domainDNS\"],\"objectSid\":\"{DOMAIN_SID}\"}},\
        {{\"distinguishedName\":\"CN=a\",\"objectClass\":[\"user\"],\"objectSid\":\"{ADMIN_SID}\",\"lastLogonTimestamp\":{}}},\
        {{\"distinguishedName\":\"CN=b\",\"objectClass\":[\"user\"],\"lastLogonTimestamp\":0}},\
        {{\"distinguishedName\":\"CN=c\",\"objectClass\":[\"user\"],\"lastLogonTimestamp\":9223372036854775807}}]}}",
        filetime_of(CAPTURED)
    );
    let read = read_captured(text.as_bytes(), &Limits::default())?;
    let row = row_of(indicator_of(&read.snapshot, read.captured.as_deref(), NOW, TENANT)?)?;
    assert_eq!(row.value, TWO);
    assert!(row.source.contains("never_logged=2;"));
    Ok(())
}


#[test]
fn the_forty_five_day_edge_is_fresh_and_one_second_more_is_stale() -> Result<(), Box<dyn Error>> {
    let edge = user("CN=edge", Some(CAPTURED - FORTY_FIVE * DAYS));
    assert_eq!(row_for(with(vec![edge]))?.value, 0);
    let over = user("CN=over", Some(CAPTURED - FORTY_FIVE * DAYS - 1));
    assert_eq!(row_for(with(vec![over]))?.value, 1);
    assert_eq!(INDICATOR_INACTIVE_DAYS, FORTY_FIVE);
    Ok(())
}


#[test]
fn a_logon_after_the_capture_is_inactive_and_counted_as_future() -> Result<(), Box<dyn Error>> {
    let soon = user("CN=soon", Some(CAPTURED + MINUTE));
    let far = user("CN=far", Some(YEAR_9999_UNIX - 1));
    let row = row_for(with(vec![soon, far]))?;
    assert_eq!(row.value, TWO);
    assert!(row.source.contains("never_logged=0;future=2;"));
    Ok(())
}


#[test]
fn inactivity_is_measured_from_the_capture_not_from_now() -> Result<(), Box<dyn Error>> {
    let earlier_unix = NOW - FORTY * HOUR;
    let late = user("CN=late", Some(earlier_unix - FORTY_FOUR * DAYS));
    let admin = entry("CN=Administrator", &["user"], UAC_NORMAL, Some(earlier_unix), Some(ADMIN_SID));
    let row = row_of(indicator_of(
        &snapshot_of(vec![domain_entry(), admin, late]),
        Some("2023-11-13T06:13:20Z"),
        NOW,
        TENANT,
    )?)?;
    assert_eq!(row.value, 0);
    Ok(())
}


#[test]
fn an_unknown_class_reads_as_a_user_and_a_known_computer_does_not() -> Result<(), Box<dyn Error>> {
    let nameless = entry("CN=nameless", &[], UAC_NORMAL, None, None);
    let mut gapped = entry("CN=gapped", &["top"], UAC_NORMAL, None, None);
    gapped.gaps.push(Gap {
        field: "objectClass",
        dropped: 1,
        over_limit: false,
    });
    let mut gapped_computer = entry("CN=gc", &["computer"], UAC_NORMAL, None, None);
    gapped_computer.gaps.push(Gap {
        field: "objectClass",
        dropped: 1,
        over_limit: false,
    });
    let mut other_gap = entry("CN=og", &["group"], UAC_NORMAL, None, None);
    other_gap.gaps.push(Gap {
        field: "memberOf",
        dropped: 1,
        over_limit: false,
    });
    let off = entry("CN=off", &[], UAC_DISABLED, None, None);
    let row = row_for(with(vec![nameless, gapped, gapped_computer, other_gap, off]))?;
    assert_eq!(row.value, TWO);
    Ok(())
}


#[test]
fn an_unreadable_entry_adds_one_inactive_account() -> Result<(), Box<dyn Error>> {
    let mut snapshot = snapshot_of(base());
    snapshot.unreadable.push(Unreadable {
        index: THREE,
        field: "objectSid",
        reason: "not a SID",
        dn_digest: "0011223344556677".to_owned(),
        group_risk: false,
        account: None,
        sid: None,
    });
    let row = row_of(indicator_of(&snapshot, Some(CAPTURED_TEXT), NOW, TENANT)?)?;
    assert_eq!(row.value, 1);
    assert!(row
        .source
        .contains("entries=3;accounts=2;inactive=1;never_logged=0;future=0;unreadable=1;"));
    Ok(())
}


#[test]
fn a_bound_hit_emits_nothing_with_a_counts_only_warning() -> Result<(), Box<dyn Error>> {
    let read = read_captured(
        "[{},{},{}]".as_bytes(),
        &Limits {
            max_entries: TWO,
            ..Limits::default()
        },
    )?;
    assert_eq!(refusal_of(&read.snapshot, Some(CAPTURED_TEXT))?, Refusal::BoundHit);
    let outcome = indicator_of(&read.snapshot, Some(CAPTURED_TEXT), NOW, TENANT)?;
    assert_eq!(indicator_json(&outcome), "[]");
    assert_eq!(
        warning_line(&outcome).as_deref(),
        Some("no indicator: a global bound of the snapshot was reached (entries=0)")
    );
    Ok(())
}


#[test]
fn an_incomplete_snapshot_is_never_a_figure() -> Result<(), Box<dyn Error>> {
    assert_eq!(refusal_of(&snapshot_of(Vec::new()), Some(CAPTURED_TEXT))?, Refusal::NoDomain);
    let two_domains = vec![
        domain_entry(),
        entry("DC=other", &["domain"], 0, None, Some(OTHER_DOMAIN_SID)),
        administrator(),
    ];
    assert_eq!(refusal_of(&snapshot_of(two_domains), Some(CAPTURED_TEXT))?, Refusal::NoDomain);
    let no_domain_object = vec![entry("CN=Domain Admins", &["group"], 0, None, Some(ADMINS_GROUP_SID)), administrator()];
    assert_eq!(refusal_of(&snapshot_of(no_domain_object), Some(CAPTURED_TEXT))?, Refusal::NoDomainObject);
    assert_eq!(
        refusal_of(&snapshot_of(vec![domain_entry()]), Some(CAPTURED_TEXT))?,
        Refusal::NoAdministrator
    );
    let foreign_admin = entry("CN=Administrator", &["user"], UAC_NORMAL, None, Some(OTHER_ADMIN_SID));
    assert_eq!(
        refusal_of(&snapshot_of(vec![domain_entry(), foreign_admin]), Some(CAPTURED_TEXT))?,
        Refusal::NoAdministrator
    );
    let group_500 = entry("CN=g", &["group"], 0, None, Some(ADMIN_SID));
    assert_eq!(
        refusal_of(&snapshot_of(vec![domain_entry(), group_500]), Some(CAPTURED_TEXT))?,
        Refusal::NoAdministrator
    );
    let no_class = vec![
        entry("DC=lab,DC=test", &[], 0, None, Some(DOMAIN_SID)),
        entry("CN=Administrator", &[], UAC_NORMAL, None, Some(ADMIN_SID)),
    ];
    assert_eq!(refusal_of(&snapshot_of(no_class), Some(CAPTURED_TEXT))?, Refusal::NoDomain);
    Ok(())
}


#[test]
fn the_capture_time_is_bounded_on_both_sides() -> Result<(), Box<dyn Error>> {
    let snapshot = snapshot_of(base());
    assert_eq!(refusal_of(&snapshot, None)?, Refusal::NoCaptureTime);
    assert_eq!(refusal_of(&snapshot, Some("yesterday"))?, Refusal::BadCaptureTime);
    assert_eq!(refusal_of(&snapshot, Some("9999-12-31T23:00:00-02:00"))?, Refusal::BadCaptureTime);
    assert_eq!(refusal_of(&snapshot, Some("0000-01-01T00:00:00+05:00"))?, Refusal::BadCaptureTime);
    assert_eq!(refusal_of(&snapshot, Some("2023-11-14T22:13:21Z"))?, Refusal::CaptureInFuture);
    assert_eq!(refusal_of(&snapshot, Some("9999-12-31T00:00:00Z"))?, Refusal::CaptureInFuture);
    assert_eq!(refusal_of(&snapshot, Some("2023-11-12T22:13:19Z"))?, Refusal::CaptureTooOld);
    assert_eq!(
        captured_of(Some("2023-11-12T22:13:20Z"), NOW)
            .map_err(|refusal| format!("{refusal:?}"))?
            .unix_timestamp(),
        NOW - FORTY_EIGHT * HOUR
    );
    assert_eq!(
        captured_of(Some("2023-11-14T22:13:20Z"), NOW)
            .map_err(|refusal| format!("{refusal:?}"))?
            .unix_timestamp(),
        NOW
    );
    Ok(())
}


#[test]
fn the_observed_time_is_the_capture_time_in_utc() -> Result<(), Box<dyn Error>> {
    let outcome = indicator_of(&snapshot_of(base()), Some(CAPTURED_OFFSET_TEXT), NOW, TENANT)?;
    assert_eq!(row_of(outcome)?.observed_at, CAPTURED_TEXT);
    let early = indicator_of(&snapshot_of(base()), Some("2023-11-13T01:02:03.456Z"), NOW, TENANT)?;
    assert_eq!(row_of(early)?.observed_at, "2023-11-13T01:02:03Z");
    Ok(())
}


#[test]
fn the_figure_does_not_depend_on_entry_order() -> Result<(), Box<dyn Error>> {
    let extra = vec![
        user("CN=a", None),
        user("CN=b", Some(CAPTURED)),
        user("CN=c", Some(CAPTURED - FORTY_SIX * DAYS)),
    ];
    let forward = row_for(with(extra.clone()))?;
    let mut reversed_entries = with(extra);
    reversed_entries.reverse();
    assert_eq!(row_for(reversed_entries)?, forward);
    Ok(())
}


#[test]
fn the_thresholds_file_has_no_effect_on_the_indicator() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("thresholds.yaml");
    std::fs::write(&path, THRESHOLDS_BIG)?;
    let thresholds = load_thresholds(&path)?;
    assert!(i64::from(thresholds.inactive_days) > INDICATOR_INACTIVE_DAYS);
    let stale = user("CN=stale", Some(CAPTURED - FORTY_SIX * DAYS));
    assert_eq!(row_for(with(vec![stale]))?.value, 1);
    Ok(())
}


#[test]
fn the_caller_clock_is_bounded() -> Result<(), Box<dyn Error>> {
    assert_eq!(checked_now(NOW + SKEW_BELOW, NOW)?, NOW + SKEW_BELOW);
    assert_eq!(checked_now(NOW - SKEW_BELOW, NOW)?, NOW - SKEW_BELOW);
    assert!(matches!(
        checked_now(NOW + SKEW_ABOVE, NOW),
        Err(IndicatorError::ClockSkew { max: MAX_CLOCK_SKEW_SECONDS })
    ));
    assert!(checked_now(NOW - FORTY_FIVE * HOUR, NOW).is_err());
    assert!(checked_now(NOW + FORTY_FIVE * HOUR, NOW).is_err());
    Ok(())
}


#[test]
fn the_tenant_follows_the_store_grammar() -> Result<(), Box<dyn Error>> {
    let snapshot = snapshot_of(base());
    let long = "a".repeat(FORTY_EIGHT as usize + FORTY_EIGHT as usize);
    ["", "-x", "a b", "a/b", "t\u{212a}", long.as_str()].iter().try_for_each(|tenant| {
        match indicator_of(&snapshot, Some(CAPTURED_TEXT), NOW, tenant) {
            Err(IndicatorError::InvalidTenant(_)) => Ok(()),
            other => Err(format!("accepted {tenant:?}: {other:?}")),
        }
    })?;
    assert!(indicator_of(&snapshot, Some(CAPTURED_TEXT), NOW, "a.b_c-1").is_ok());
    Ok(())
}


#[test]
fn the_source_holds_integers_only_and_stays_short() -> Result<(), Box<dyn Error>> {
    let worst = IndicatorCounts {
        entries: MAX_ENTRIES,
        accounts: MAX_ENTRIES,
        inactive: MAX_ENTRIES,
        never_logged: MAX_ENTRIES,
        future: MAX_ENTRIES,
        unreadable: MAX_ENTRIES,
    };
    let source = source_of(&worst, MAX_NOW);
    assert!(source.len() < MAX_SOURCE_LENGTH);
    Ok(())
}


#[test]
fn a_hostile_name_never_reaches_the_output() -> Result<(), Box<dyn Error>> {
    let long_name = "n".repeat(TEN_KIB);
    let text = format!(
        "{{\"captured\":\"{CAPTURED_TEXT}\",\"entries\":[\
        {{\"distinguishedName\":\"DC=x\",\"objectClass\":[\"domainDNS\"],\"objectSid\":\"{DOMAIN_SID}\"}},\
        {{\"distinguishedName\":\"CN=a\",\"objectClass\":[\"user\"],\"objectSid\":\"{ADMIN_SID}\",\"lastLogonTimestamp\":{}}},\
        {{\"distinguishedName\":\"CN=esc\",\"objectClass\":[\"user\"],\"sAMAccountName\":\"{ESC_NAME}\"}},\
        {{\"distinguishedName\":\"CN=long\",\"objectClass\":[\"user\"],\"sAMAccountName\":\"{long_name}\"}}]}}",
        filetime_of(CAPTURED)
    );
    let read = read_captured(text.as_bytes(), &Limits::default())?;
    let outcome = indicator_of(&read.snapshot, read.captured.as_deref(), NOW, TENANT)?;
    let json = indicator_json(&outcome);
    assert!(!json.contains("evil"));
    assert!(!json.contains("nnnn"));
    assert!(!json.contains("u001b"));
    assert!(row_of(outcome)?.source.contains("unreadable=2;"));
    Ok(())
}


#[test]
fn the_json_is_one_row_object_or_an_empty_array() -> Result<(), Box<dyn Error>> {
    let outcome = indicator_of(&snapshot_of(base()), Some(CAPTURED_TEXT), NOW, TENANT)?;
    let parsed: serde_json::Value = serde_json::from_str(&indicator_json(&outcome))?;
    let object = parsed.get(0).ok_or("no element")?;
    assert_eq!(object.get("name").and_then(serde_json::Value::as_str), Some(INDICATOR_NAME));
    assert_eq!(object.get("value").and_then(serde_json::Value::as_u64), Some(0));
    assert_eq!(object.as_object().map(serde_json::Map::len), Some(FIVE));
    assert!(warning_line(&outcome).is_none());
    Ok(())
}


#[test]
fn every_refusal_has_its_own_fixed_reason() -> Result<(), Box<dyn Error>> {
    let all = [
        Refusal::BoundHit,
        Refusal::NoCaptureTime,
        Refusal::BadCaptureTime,
        Refusal::CaptureInFuture,
        Refusal::CaptureTooOld,
        Refusal::NoDomain,
        Refusal::NoDomainObject,
        Refusal::NoAdministrator,
    ];
    let reasons: std::collections::BTreeSet<&str> = all.iter().map(|refusal| reason_of(*refusal)).collect();
    assert_eq!(reasons.len(), all.len());
    Ok(())
}


#[test]
fn the_object_form_gives_the_capture_text_and_the_bare_array_none() -> Result<(), Box<dyn Error>> {
    let object = read_captured(
        format!("  {{\"x\":[1],\"captured\":\"{CAPTURED_TEXT}\",\"entries\":[{{\"distinguishedName\":\"a\"}}]}}").as_bytes(),
        &Limits::default(),
    )?;
    assert_eq!(object.captured.as_deref(), Some(CAPTURED_TEXT));
    assert_eq!(object.snapshot.entries.len(), 1);
    let bare = read_captured("[{\"distinguishedName\":\"a\"}]".as_bytes(), &Limits::default())?;
    assert_eq!(bare.captured, None);
    assert_eq!(refusal_of(&bare.snapshot, bare.captured.as_deref())?, Refusal::NoCaptureTime);
    assert_eq!(
        read_snapshot("{\"entries\":[{\"distinguishedName\":\"a\"}]}".as_bytes(), &Limits::default())?
            .entries
            .len(),
        1
    );
    Ok(())
}


#[test]
fn a_refused_capture_text_reads_as_absent() -> Result<(), Box<dyn Error>> {
    ["null", "12", "\"\"", "[]"].iter().try_for_each(|captured| {
        let text = format!("{{\"captured\":{captured},\"entries\":[]}}");
        let read = read_captured(text.as_bytes(), &Limits::default())?;
        match read.captured {
            None => Ok(()),
            Some(found) => Err(format!("kept {found}").into()),
        }
    })
}


#[test]
fn a_broken_object_root_is_an_error() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        read_captured("{\"captured\":\"x\"}".as_bytes(), &Limits::default()),
        Err(SnapshotError::MissingEntries)
    ));
    assert!(matches!(
        read_captured("{\"entries\":[],\"entries\":[]}".as_bytes(), &Limits::default()),
        Err(SnapshotError::Malformed { .. })
    ));
    assert!(matches!(
        read_captured("{\"entries\":{}}".as_bytes(), &Limits::default()),
        Err(SnapshotError::Malformed { .. })
    ));
    assert!(matches!(
        read_captured("{".as_bytes(), &Limits::default()),
        Err(SnapshotError::Malformed { .. })
    ));
    Ok(())
}


#[test]
fn the_entries_of_the_object_form_are_bounded_like_the_array() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_entries: 1,
        ..Limits::default()
    };
    let read = read_captured(
        format!("{{\"captured\":\"{CAPTURED_TEXT}\",\"entries\":[{{}},{{}}]}}").as_bytes(),
        &limits,
    )?;
    assert_eq!(read.snapshot.bounds.len(), 1);
    let bytes = Limits {
        max_bytes: FOUR as u64,
        ..Limits::default()
    };
    let over = read_captured("{\"entries\":[]}".as_bytes(), &bytes)?;
    assert_eq!(over.captured, None);
    assert_eq!(over.snapshot.bounds.len(), 1);
    Ok(())
}
