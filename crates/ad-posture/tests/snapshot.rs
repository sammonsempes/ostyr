use ad_posture::error::SnapshotError;
use ad_posture::limits::{Limits, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_TEXT_BYTES, DEFAULT_MAX_VALUES};
use ad_posture::model::{Entry, Snapshot};
use ad_posture::snapshot::{is_sid, read_snapshot, text_problem};
use std::error::Error;
use std::io::{Error as IoError, Read};


const SMALL: usize = 2;


const THREE: usize = 3;


const THIRD: usize = 2;


const INVALID_UTF8: [u8; 1] = [255];


const THREE_VALUES: &str = "[1,2,3]";


const TICKS_2023: u64 = 133_444_736_000_000_000;


const UNIX_2023: i64 = 1_700_000_000;


const UAC_USER: u32 = 512;


const OVER_U32: u64 = 4_294_967_296;


const TINY_BYTES: u64 = 8;


const SECRET: &str = "hunter2-secret-text";


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(IoError::other("disk gone"))
    }
}


fn limits() -> Limits {
    Limits::default()
}


fn read(text: &str, bounds: &Limits) -> Result<Snapshot, SnapshotError> {
    read_snapshot(text.as_bytes(), bounds)
}


fn one(fields: &str) -> String {
    format!("[{{\"distinguishedName\":\"CN=a,DC=x\"{fields}}}]")
}


fn refused(text: &str, bounds: &Limits) -> Result<SnapshotError, Box<dyn Error>> {
    Ok(read(text, bounds).err().ok_or("snapshot accepted")?)
}


#[test]
fn a_full_entry_is_read() -> Result<(), Box<dyn Error>> {
    let text = format!(
        "[{{\"distinguishedName\":\"CN=svc,DC=x\",\"objectClass\":[\"top\",\"user\"],\"sAMAccountName\":\"svc\",\"userAccountControl\":{UAC_USER},\
         \"servicePrincipalName\":[\"http/a\"],\"memberOf\":[\"CN=g,DC=x\"],\"pwdLastSet\":{TICKS_2023},\"lastLogonTimestamp\":{TICKS_2023},\
         \"objectSid\":\"S-1-5-21-1-2-3-1105\",\"adminCount\":1,\"extra\":{{\"deep\":[1,2]}}}}]"
    );
    let snapshot = read(&text, &limits())?;
    assert_eq!(
        snapshot.entries,
        vec![Entry {
            dn: "CN=svc,DC=x".to_owned(),
            classes: vec!["top".to_owned(), "user".to_owned()],
            account: Some("svc".to_owned()),
            uac: UAC_USER,
            spns: vec!["http/a".to_owned()],
            member_of: vec!["CN=g,DC=x".to_owned()],
            pwd_last_set: Some(UNIX_2023),
            last_logon: Some(UNIX_2023),
            sid: Some("S-1-5-21-1-2-3-1105".to_owned()),
        }]
    );
    Ok(())
}


#[test]
fn absent_and_null_attributes_take_their_defaults() -> Result<(), Box<dyn Error>> {
    let snapshot = read(&one(",\"memberOf\":null,\"userAccountControl\":null"), &limits())?;
    let entry = snapshot.entries.first().ok_or("no entry")?;
    assert_eq!(entry.uac, 0);
    assert!(entry.member_of.is_empty() && entry.classes.is_empty() && entry.spns.is_empty());
    assert!(entry.account.is_none() && entry.sid.is_none() && entry.pwd_last_set.is_none() && entry.last_logon.is_none());
    assert!(read("[]", &limits())?.entries.is_empty());
    Ok(())
}


#[test]
fn zero_and_never_filetimes_are_none() -> Result<(), Box<dyn Error>> {
    let snapshot = read(&one(",\"pwdLastSet\":0,\"lastLogonTimestamp\":9223372036854775807"), &limits())?;
    let entry = snapshot.entries.first().ok_or("no entry")?;
    assert!(entry.pwd_last_set.is_none() && entry.last_logon.is_none());
    Ok(())
}


#[test]
fn a_filetime_past_year_9999_is_refused() -> Result<(), Box<dyn Error>> {
    let past = refused(&one(",\"pwdLastSet\":9223372036854775806"), &limits())?;
    assert!(matches!(
        past,
        SnapshotError::BadFiletime {
            index: 0,
            field: "pwdLastSet",
            ..
        }
    ));
    assert!(past.source().is_some());
    let logon = refused(&one(",\"lastLogonTimestamp\":18446744073709551615"), &limits())?;
    assert!(matches!(
        logon,
        SnapshotError::BadFiletime {
            field: "lastLogonTimestamp",
            ..
        }
    ));
    Ok(())
}


#[test]
fn a_user_account_control_of_the_wrong_type_is_refused() -> Result<(), Box<dyn Error>> {
    let texts = [
        one(",\"userAccountControl\":\"512\""),
        one(",\"userAccountControl\":-1"),
        one(&format!(",\"userAccountControl\":{OVER_U32}")),
        one(",\"userAccountControl\":1.5"),
        one(",\"userAccountControl\":[512]"),
        one(",\"pwdLastSet\":\"1\""),
        one(",\"pwdLastSet\":-1"),
    ];
    texts
        .iter()
        .try_for_each(|text| match read(text, &limits()) {
            Err(SnapshotError::BadEntry {
                index: 0, field: "entry", ..
            }) => Ok(()),
            other => Err(format!("not a typed refusal: {other:?}")),
        })
        .map_err(Into::into)
}


#[test]
fn the_size_cap_applies_before_parsing() -> Result<(), Box<dyn Error>> {
    let tiny = Limits {
        max_bytes: TINY_BYTES,
        ..limits()
    };
    assert!(matches!(refused(&one(""), &tiny)?, SnapshotError::TooLarge { max: TINY_BYTES }));
    let exact = THREE_VALUES.len() as u64;
    let at_cap = Limits {
        max_bytes: exact,
        ..limits()
    };
    assert!(matches!(refused(THREE_VALUES, &at_cap)?, SnapshotError::BadEntry { .. }));
    Ok(())
}


#[test]
fn a_failing_reader_is_an_error_with_its_cause() -> Result<(), Box<dyn Error>> {
    let error = read_snapshot(FailingReader, &limits()).err().ok_or("accepted")?;
    assert!(matches!(error, SnapshotError::Read(_)));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn invalid_utf8_and_malformed_json_are_refused() -> Result<(), Box<dyn Error>> {
    let utf8 = read_snapshot(&INVALID_UTF8[..], &limits()).err().ok_or("accepted")?;
    assert!(matches!(utf8, SnapshotError::NotUtf8(_)));
    assert!(utf8.source().is_some());
    assert!(matches!(refused("[1,", &limits())?, SnapshotError::Malformed { .. }));
    assert!(matches!(refused("{}", &limits())?, SnapshotError::Malformed { .. }));
    assert!(refused("", &limits())?.to_string().contains("line"));
    Ok(())
}


#[test]
fn the_entry_count_is_checked_before_any_entry_is_built() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_entries: SMALL,
        ..limits()
    };
    assert!(matches!(
        refused(THREE_VALUES, &bounds)?,
        SnapshotError::TooManyEntries { count: THREE, max: SMALL }
    ));
    assert!(matches!(refused("[1,2]", &bounds)?, SnapshotError::BadEntry { index: 0, .. }));
    Ok(())
}


#[test]
fn the_value_count_is_checked_before_any_value_is_built() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_values: SMALL,
        ..limits()
    };
    let error = refused(&one(&format!(",\"memberOf\":{THREE_VALUES}")), &bounds)?;
    assert!(matches!(
        error,
        SnapshotError::TooManyValues {
            index: 0,
            field: "memberOf",
            count: THREE,
            max: SMALL
        }
    ));
    let spn = refused(&one(&format!(",\"servicePrincipalName\":{THREE_VALUES}")), &bounds)?;
    assert!(matches!(
        spn,
        SnapshotError::TooManyValues {
            field: "servicePrincipalName",
            ..
        }
    ));
    let classes = refused(&one(&format!(",\"objectClass\":{THREE_VALUES}")), &bounds)?;
    assert!(matches!(classes, SnapshotError::TooManyValues { field: "objectClass", .. }));
    assert!(read(&one(",\"memberOf\":[\"a\",\"b\"]"), &bounds).is_ok());
    Ok(())
}


#[test]
fn a_collection_of_the_wrong_shape_is_refused() -> Result<(), Box<dyn Error>> {
    let texts = [
        one(",\"memberOf\":\"CN=g\""),
        one(",\"memberOf\":{}"),
        one(",\"memberOf\":[1]"),
        one(",\"memberOf\":[[\"a\"]]"),
        one(",\"sAMAccountName\":5"),
    ];
    texts
        .iter()
        .try_for_each(|text| match read(text, &limits()) {
            Err(SnapshotError::BadEntry { .. }) => Ok(()),
            other => Err(format!("not a shape refusal: {other:?}")),
        })
        .map_err(Into::into)
}


#[test]
fn an_entry_without_a_dn_or_not_an_object_is_refused() -> Result<(), Box<dyn Error>> {
    assert!(matches!(refused("[{}]", &limits())?, SnapshotError::BadEntry { field: "entry", .. }));
    assert!(matches!(refused("[1]", &limits())?, SnapshotError::BadEntry { field: "entry", .. }));
    assert!(matches!(
        refused("[{\"distinguishedName\":1}]", &limits())?,
        SnapshotError::BadEntry {
            field: "distinguishedName",
            ..
        }
    ));
    assert!(matches!(
        refused("[{\"distinguishedName\":\"a\",\"distinguishedName\":\"b\"}]", &limits())?,
        SnapshotError::BadEntry { .. }
    ));
    Ok(())
}


#[test]
fn a_text_above_its_bound_is_refused_before_it_is_decoded() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_text_bytes: 1,
        ..limits()
    };
    let undecoded = refused("[{\"distinguishedName\":[1,1,1,1,1,1,1,1]}]", &bounds)?;
    assert!(matches!(undecoded, SnapshotError::BadText { reason: "too long", .. }));
    let raw = refused("[{\"distinguishedName\":\"abcdefghij\"}]", &bounds)?;
    assert!(matches!(
        raw,
        SnapshotError::BadText {
            field: "distinguishedName",
            reason: "too long",
            ..
        }
    ));
    let wide = Limits {
        max_text_bytes: THREE,
        ..limits()
    };
    let decoded = refused("[{\"distinguishedName\":\"abcd\"}]", &wide)?;
    assert!(matches!(decoded, SnapshotError::BadText { reason: "too long", .. }));
    assert!(read("[{\"distinguishedName\":\"abc\"}]", &wide).is_ok());
    Ok(())
}


#[test]
fn an_empty_text_is_refused() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        refused("[{\"distinguishedName\":\"\"}]", &limits())?,
        SnapshotError::BadText { reason: "empty", .. }
    ));
    assert!(matches!(
        refused(&one(",\"memberOf\":[\"\"]"), &limits())?,
        SnapshotError::BadText { field: "memberOf", .. }
    ));
    Ok(())
}


#[test]
fn a_text_with_an_unsafe_character_is_refused() -> Result<(), Box<dyn Error>> {
    let texts = [
        "[{\"distinguishedName\":\"CN=a\\nSevere Kerberoastable CN=fake\"}]",
        "[{\"distinguishedName\":\"CN=a\\u202eBidi\"}]",
        "[{\"distinguishedName\":\"CN=a\u{202e}Bidi\"}]",
        "[{\"distinguishedName\":\"CN=a\\u0000\"}]",
        "[{\"distinguishedName\":\"CN=a\u{3164}\"}]",
        "[{\"distinguishedName\":\"CN=a\u{2028}\"}]",
    ];
    texts
        .iter()
        .try_for_each(|text| match read(text, &limits()) {
            Err(SnapshotError::BadText {
                reason: "unsafe character", ..
            }) => Ok(()),
            other => Err(format!("not refused as unsafe: {other:?}")),
        })
        .map_err(Into::into)
}


#[test]
fn every_text_field_is_checked_for_unsafe_characters() -> Result<(), Box<dyn Error>> {
    let fields = ["sAMAccountName", "objectSid"];
    fields.iter().try_for_each(|field| {
        let error = refused(&one(&format!(",\"{field}\":\"a\\nb\"")), &limits())?;
        assert!(matches!(error, SnapshotError::BadText { .. }));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let lists = ["objectClass", "servicePrincipalName", "memberOf"];
    lists.iter().try_for_each(|field| {
        let error = refused(&one(&format!(",\"{field}\":[\"a\\nb\"]")), &limits())?;
        assert!(matches!(error, SnapshotError::BadText { .. }));
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_sid_must_be_ascii_sid_text() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        refused(&one(",\"objectSid\":\"hello\""), &limits())?,
        SnapshotError::BadText {
            field: "objectSid",
            reason: "not a SID",
            ..
        }
    ));
    assert!(matches!(
        refused(&one(",\"objectSid\":\"S-1-5-\u{0661}\""), &limits())?,
        SnapshotError::BadText { reason: "not a SID", .. }
    ));
    assert!(is_sid("S-1-5-32-544") && !is_sid("S") && !is_sid("S-1-x") && !is_sid(""));
    assert!(read(&one(",\"objectSid\":\"S-1-5-32-544\""), &limits()).is_ok());
    Ok(())
}


#[test]
fn a_repeated_dn_is_refused_whatever_its_case() -> Result<(), Box<dyn Error>> {
    let text = "[{\"distinguishedName\":\"CN=Admin,DC=x\"},{\"distinguishedName\":\"CN=other,DC=x\"},{\"distinguishedName\":\"cn=admin,dc=X\"}]";
    assert!(matches!(refused(text, &limits())?, SnapshotError::DuplicateDn { index: THIRD }));
    Ok(())
}


#[test]
fn an_error_never_carries_the_input_text() -> Result<(), Box<dyn Error>> {
    let texts = [
        format!("[{{\"distinguishedName\":\"{SECRET}\\n\"}}]"),
        format!("[{{\"distinguishedName\":\"{SECRET}\",\"userAccountControl\":\"{SECRET}\"}}]"),
        format!("[{{\"distinguishedName\":\"{SECRET}\"}},{{\"distinguishedName\":\"{SECRET}\"}}]"),
        format!("[\"{SECRET}\"]"),
        SECRET.to_string(),
    ];
    texts.iter().try_for_each(|text| {
        let error = refused(text, &limits())?;
        assert!(!error.to_string().contains(SECRET) && !format!("{error:?}").contains(SECRET));
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn the_default_bounds_are_the_documented_ones() -> Result<(), Box<dyn Error>> {
    let bounds = Limits::default();
    assert_eq!(bounds.max_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(bounds.max_entries, DEFAULT_MAX_ENTRIES);
    assert_eq!(bounds.max_values, DEFAULT_MAX_VALUES);
    assert_eq!(bounds.max_text_bytes, DEFAULT_MAX_TEXT_BYTES);
    assert_eq!(text_problem("a", DEFAULT_MAX_TEXT_BYTES), None);
    Ok(())
}
