use ad_posture::error::{EntryError, SnapshotError};
use ad_posture::limits::{Limits, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_TEXT_BYTES, DEFAULT_MAX_TOTAL_VALUES, DEFAULT_MAX_VALUES};
use ad_posture::model::{Entry, Snapshot, Unreadable};
use ad_posture::snapshot::{digest_prefix, entry_of, group_risk, is_sid, read_snapshot, text_problem, total_values};
use serde_json::value::RawValue;
use std::error::Error;
use std::io::{Error as IoError, Read};


const SMALL: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const INVALID_UTF8: [u8; 1] = [255];


const THREE_VALUES: &str = "[1,2,3]";


const TICKS_2023: u64 = 133_444_736_000_000_000;


const UNIX_2023: i64 = 1_700_000_000;


const UAC_USER: u32 = 512;


const OVER_U32: u64 = 4_294_967_296;


const TINY_BYTES: u64 = 8;


const SECRET: &str = "hunter2-secret-text";


const DIGEST_OF_A: &str = "ca978112ca1bbdca";


const DIGEST_HEX_LENGTH: usize = 16;


const ADMINS_SID: &str = "S-1-5-21-1-2-3-512";


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


fn set_aside(text: &str, bounds: &Limits) -> Result<Unreadable, Box<dyn Error>> {
    let snapshot = read(text, bounds)?;
    assert!(snapshot.entries.is_empty(), "entry was read");
    assert_eq!(snapshot.unreadable.len(), 1);
    Ok(snapshot.unreadable.first().ok_or("none")?.clone())
}


fn token(text: &str) -> Result<Box<RawValue>, Box<dyn Error>> {
    Ok(RawValue::from_string(text.to_owned())?)
}


fn is_set_aside(text: &str, field: &str, reason: &str) -> Result<(), Box<dyn Error>> {
    let item = set_aside(text, &limits())?;
    assert_eq!((item.field, item.reason), (field, reason), "{text}");
    Ok(())
}


#[test]
fn a_full_entry_is_read() -> Result<(), Box<dyn Error>> {
    let text = format!(
        "[{{\"distinguishedName\":\"CN=svc,DC=x\",\"objectClass\":[\"top\",\"user\"],\"sAMAccountName\":\"svc\",\"userAccountControl\":{UAC_USER},\
         \"servicePrincipalName\":[\"http/a\"],\"memberOf\":[\"CN=g,DC=x\"],\"pwdLastSet\":{TICKS_2023},\"lastLogonTimestamp\":{TICKS_2023},\
         \"objectSid\":\"S-1-5-21-1-2-3-1105\",\"adminCount\":1,\"extra\":{{\"deep\":[1,2]}}}}]"
    );
    let snapshot = read(&text, &limits())?;
    assert!(snapshot.unreadable.is_empty());
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
fn a_filetime_past_year_9999_sets_only_that_entry_aside() -> Result<(), Box<dyn Error>> {
    is_set_aside(&one(",\"pwdLastSet\":9223372036854775806"), "pwdLastSet", "FILETIME out of range")?;
    is_set_aside(
        &one(",\"lastLogonTimestamp\":18446744073709551615"),
        "lastLogonTimestamp",
        "FILETIME out of range",
    )?;
    let error = entry_of(&token("{\"distinguishedName\":\"a\",\"pwdLastSet\":18446744073709551615}")?, &limits())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, EntryError::BadFiletime { field: "pwdLastSet", .. }));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn a_number_of_the_wrong_type_sets_only_that_entry_aside() -> Result<(), Box<dyn Error>> {
    let texts = [
        one(",\"userAccountControl\":\"512\""),
        one(",\"userAccountControl\":-1"),
        one(&format!(",\"userAccountControl\":{OVER_U32}")),
        one(",\"userAccountControl\":1.5"),
        one(",\"userAccountControl\":[512]"),
    ];
    texts
        .iter()
        .try_for_each(|text| is_set_aside(text, "userAccountControl", "wrong shape"))?;
    is_set_aside(&one(",\"pwdLastSet\":\"1\""), "pwdLastSet", "wrong shape")?;
    is_set_aside(&one(",\"pwdLastSet\":-1"), "pwdLastSet", "wrong shape")
}


#[test]
fn one_bad_entry_never_blanks_the_others() -> Result<(), Box<dyn Error>> {
    let text = "[{\"distinguishedName\":\"CN=ok1\"},{\"distinguishedName\":\"CN=a\\u202eevil\"},{\"distinguishedName\":\"CN=ok2\"},\
                {\"distinguishedName\":\"CN=b\",\"memberOf\":[1]},7]";
    let snapshot = read(text, &limits())?;
    let names: Vec<&str> = snapshot.entries.iter().map(|entry| entry.dn.as_str()).collect();
    assert_eq!(names, vec!["CN=ok1", "CN=ok2"]);
    let indexes: Vec<usize> = snapshot.unreadable.iter().map(|item| item.index).collect();
    assert_eq!(indexes, vec![1, THREE, FOUR]);
    Ok(())
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
    assert_eq!(read(THREE_VALUES, &at_cap)?.unreadable.len(), THREE);
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
    assert_eq!(read("[1,2]", &bounds)?.unreadable.len(), SMALL);
    Ok(())
}


#[test]
fn the_total_value_count_is_checked_before_any_value_is_built() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_total_values: THREE,
        ..limits()
    };
    let text = "[{\"distinguishedName\":\"a\",\"memberOf\":[\"x\",\"y\"],\"objectClass\":[\"z\"]},\
                {\"distinguishedName\":\"b\",\"servicePrincipalName\":[\"w\"]}]";
    let error = refused(text, &bounds)?;
    assert!(matches!(error, SnapshotError::TooManyTotalValues { count: FOUR, max: THREE }));
    let within = Limits {
        max_total_values: FOUR,
        ..limits()
    };
    assert_eq!(read(text, &within)?.entries.len(), SMALL);
    Ok(())
}


#[test]
fn a_list_above_its_own_bound_builds_nothing_and_adds_nothing_to_the_total() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_values: SMALL,
        max_total_values: 1,
        ..limits()
    };
    let text =
        "[{\"distinguishedName\":\"a\",\"memberOf\":[1,2,3,4,5,6,7,8],\"objectClass\":[\"z\"]},7,{\"distinguishedName\":\"b\",\"objectClass\":5}]";
    let snapshot = read(text, &bounds)?;
    assert_eq!(snapshot.unreadable.len(), THREE);
    let raws = [token("{\"memberOf\":[1,2,3]}")?, token("{\"memberOf\":[1,2],\"objectClass\":[1]}")?];
    let refs: Vec<&RawValue> = raws.iter().map(|raw| &**raw).collect();
    assert_eq!(total_values(&refs, &bounds), THREE);
    Ok(())
}


#[test]
fn the_value_count_of_one_list_sets_only_that_entry_aside() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_values: SMALL,
        ..limits()
    };
    let item = set_aside(&one(&format!(",\"memberOf\":{THREE_VALUES}")), &bounds)?;
    assert_eq!((item.field, item.reason), ("memberOf", "too many values"));
    let spn = set_aside(&one(&format!(",\"servicePrincipalName\":{THREE_VALUES}")), &bounds)?;
    assert_eq!(spn.field, "servicePrincipalName");
    let classes = set_aside(&one(&format!(",\"objectClass\":{THREE_VALUES}")), &bounds)?;
    assert_eq!(classes.field, "objectClass");
    assert!(read(&one(",\"memberOf\":[\"a\",\"b\"]"), &bounds)?.unreadable.is_empty());
    let error = entry_of(&token(&format!("{{\"distinguishedName\":\"a\",\"memberOf\":{THREE_VALUES}}}"))?, &bounds)
        .err()
        .ok_or("accepted")?;
    assert!(matches!(
        error,
        EntryError::TooManyValues {
            field: "memberOf",
            count: THREE,
            max: SMALL
        }
    ));
    Ok(())
}


#[test]
fn a_collection_of_the_wrong_shape_sets_the_entry_aside() -> Result<(), Box<dyn Error>> {
    let texts = [
        one(",\"memberOf\":\"CN=g\""),
        one(",\"memberOf\":{}"),
        one(",\"memberOf\":[1]"),
        one(",\"memberOf\":[[\"a\"]]"),
        one(",\"sAMAccountName\":5"),
    ];
    texts.iter().try_for_each(|text| {
        let item = set_aside(text, &limits())?;
        assert_eq!(item.reason, "wrong shape", "{text}");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn an_entry_without_a_dn_or_not_an_object_is_set_aside() -> Result<(), Box<dyn Error>> {
    is_set_aside("[{}]", "distinguishedName", "wrong shape")?;
    is_set_aside("[{\"distinguishedName\":null}]", "distinguishedName", "wrong shape")?;
    is_set_aside("[1]", "entry", "wrong shape")?;
    is_set_aside("[{\"distinguishedName\":1}]", "distinguishedName", "wrong shape")?;
    is_set_aside("[{\"distinguishedName\":\"a\",\"distinguishedName\":\"b\"}]", "entry", "wrong shape")
}


#[test]
fn a_text_above_its_bound_is_set_aside_before_it_is_decoded() -> Result<(), Box<dyn Error>> {
    let bounds = Limits {
        max_text_bytes: 1,
        ..limits()
    };
    assert_eq!(set_aside("[{\"distinguishedName\":[1,1,1,1,1,1,1,1]}]", &bounds)?.reason, "too long");
    assert_eq!(set_aside("[{\"distinguishedName\":\"abcdefghij\"}]", &bounds)?.reason, "too long");
    let wide = Limits {
        max_text_bytes: THREE,
        ..limits()
    };
    assert_eq!(set_aside("[{\"distinguishedName\":\"abcd\"}]", &wide)?.reason, "too long");
    assert!(read("[{\"distinguishedName\":\"abc\"}]", &wide)?.unreadable.is_empty());
    Ok(())
}


#[test]
fn an_empty_text_is_set_aside() -> Result<(), Box<dyn Error>> {
    is_set_aside("[{\"distinguishedName\":\"\"}]", "distinguishedName", "empty")?;
    is_set_aside(&one(",\"memberOf\":[\"\"]"), "memberOf", "empty")
}


#[test]
fn a_text_with_an_unsafe_character_is_set_aside() -> Result<(), Box<dyn Error>> {
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
        .try_for_each(|text| is_set_aside(text, "distinguishedName", "unsafe character"))
}


#[test]
fn every_text_field_is_checked_for_unsafe_characters() -> Result<(), Box<dyn Error>> {
    ["sAMAccountName", "objectSid"].iter().try_for_each(|field| {
        let item = set_aside(&one(&format!(",\"{field}\":\"a\\nb\"")), &limits())?;
        assert_eq!(item.field, *field);
        Ok::<(), Box<dyn Error>>(())
    })?;
    ["objectClass", "servicePrincipalName", "memberOf"].iter().try_for_each(|field| {
        let item = set_aside(&one(&format!(",\"{field}\":[\"a\\nb\"]")), &limits())?;
        assert_eq!(item.field, *field);
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_sid_must_be_ascii_sid_text() -> Result<(), Box<dyn Error>> {
    is_set_aside(&one(",\"objectSid\":\"hello\""), "objectSid", "not a SID")?;
    is_set_aside(&one(",\"objectSid\":\"S-1-5-\u{0661}\""), "objectSid", "not a SID")?;
    assert!(is_sid("S-1-5-32-544") && !is_sid("S") && !is_sid("S-1-x") && !is_sid(""));
    assert!(read(&one(",\"objectSid\":\"S-1-5-32-544\""), &limits())?.unreadable.is_empty());
    Ok(())
}


#[test]
fn every_entry_sharing_a_dn_is_set_aside_by_exact_bytes() -> Result<(), Box<dyn Error>> {
    let text = "[{\"distinguishedName\":\"CN=Admin,DC=x\"},{\"distinguishedName\":\"CN=other,DC=x\"},{\"distinguishedName\":\"CN=Admin,DC=x\"}]";
    let snapshot = read(text, &limits())?;
    assert_eq!(snapshot.entries.len(), 1);
    let both: Vec<(usize, &str)> = snapshot.unreadable.iter().map(|item| (item.index, item.reason)).collect();
    assert_eq!(both, vec![(0, "duplicate DN"), (SMALL, "duplicate DN")]);
    assert!(snapshot.unreadable.iter().all(|item| item.field == "distinguishedName"));
    Ok(())
}


#[test]
fn a_case_or_kelvin_sign_twin_is_not_a_duplicate() -> Result<(), Box<dyn Error>> {
    let text = "[{\"distinguishedName\":\"CN=KPC,DC=x\"},{\"distinguishedName\":\"CN=\u{212A}PC,DC=x\"},{\"distinguishedName\":\"cn=kpc,dc=x\"}]";
    let snapshot = read(text, &limits())?;
    assert_eq!(snapshot.entries.len(), THREE);
    assert!(snapshot.unreadable.is_empty());
    Ok(())
}


#[test]
fn a_set_aside_entry_is_named_by_a_digest_never_by_its_text() -> Result<(), Box<dyn Error>> {
    let item = set_aside(&format!("[{{\"distinguishedName\":\"{SECRET}\\n\"}}]"), &limits())?;
    assert_eq!(item.dn_digest.len(), DIGEST_HEX_LENGTH);
    assert!(item.dn_digest.chars().all(|found| found.is_ascii_hexdigit()));
    assert!(!format!("{item:?}").contains(SECRET));
    let other = set_aside(&format!("[{{\"distinguishedName\":\"{SECRET}x\\n\"}}]"), &limits())?;
    assert_ne!(item.dn_digest, other.dn_digest);
    let not_object = set_aside(&format!("[\"{SECRET}\"]"), &limits())?;
    assert!(!format!("{not_object:?}").contains(SECRET));
    assert_eq!(digest_prefix("\"a\""), digest_prefix("\"a\""));
    assert_eq!(digest_prefix("a"), DIGEST_OF_A);
    Ok(())
}


#[test]
fn whole_snapshot_errors_never_carry_the_input_text() -> Result<(), Box<dyn Error>> {
    let texts = [format!("[\"{SECRET}\""), SECRET.to_string(), format!("[{SECRET}]")];
    texts.iter().try_for_each(|text| {
        let error = refused(text, &limits())?;
        assert!(!error.to_string().contains(SECRET) && !format!("{error:?}").contains(SECRET));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let entry_error = entry_of(&token(&format!("{{\"distinguishedName\":\"{SECRET}\\n\"}}"))?, &limits())
        .err()
        .ok_or("accepted")?;
    assert!(!entry_error.to_string().contains(SECRET) && !format!("{entry_error:?}").contains(SECRET));
    Ok(())
}


#[test]
fn a_set_aside_entry_flags_a_possible_privileged_group() -> Result<(), Box<dyn Error>> {
    let bad_text = format!("[{{\"distinguishedName\":\"CN=a\\u202e\",\"objectSid\":\"{ADMINS_SID}\"}}]");
    assert!(set_aside(&bad_text, &limits())?.group_risk);
    let bad_sid = "[{\"distinguishedName\":\"CN=a\\u202e\",\"objectSid\":\"nonsense\"}]";
    assert!(set_aside(bad_sid, &limits())?.group_risk);
    let plain = "[{\"distinguishedName\":\"CN=a\\u202e\",\"objectSid\":\"S-1-5-21-1-2-3-1105\"}]";
    assert!(!set_aside(plain, &limits())?.group_risk);
    assert!(!set_aside("[{\"distinguishedName\":\"CN=a\\u202e\"}]", &limits())?.group_risk);
    assert!(!set_aside("[5]", &limits())?.group_risk);
    let duplicated = format!("[{{\"distinguishedName\":\"CN=g\",\"objectSid\":\"{ADMINS_SID}\"}},{{\"distinguishedName\":\"CN=g\"}}]");
    let snapshot = read(&duplicated, &limits())?;
    assert_eq!(snapshot.unreadable.iter().filter(|item| item.group_risk).count(), 1);
    assert!(group_risk(Some(&*token("\"S-1-5-32-544\"")?), &limits()));
    Ok(())
}


#[test]
fn the_default_bounds_are_the_documented_ones() -> Result<(), Box<dyn Error>> {
    let bounds = Limits::default();
    assert_eq!(bounds.max_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(bounds.max_entries, DEFAULT_MAX_ENTRIES);
    assert_eq!(bounds.max_values, DEFAULT_MAX_VALUES);
    assert_eq!(bounds.max_total_values, DEFAULT_MAX_TOTAL_VALUES);
    assert_eq!(bounds.max_text_bytes, DEFAULT_MAX_TEXT_BYTES);
    assert_eq!(text_problem("a", DEFAULT_MAX_TEXT_BYTES), None);
    Ok(())
}
