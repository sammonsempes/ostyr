mod common;


use common::types::TestResult;
use metrics_ingest::identity::{agent_from_ids, is_agent_id, is_canonical, single_id, stored_time, IdentityRefusal};


const LIMIT: usize = 256;


const STORED: u64 = 7;


fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}


#[test]
fn a_well_formed_id_gives_its_agent() -> TestResult {
    let id = ids(&["a:agent-7_x:12:0"]);
    assert_eq!(agent_from_ids(&id, "a", LIMIT), Ok("agent-7_x"));
    let largest = ids(&["a:b:18446744073709551615:0"]);
    assert_eq!(agent_from_ids(&largest, "a", LIMIT), Ok("b"));
    Ok(())
}


#[test]
fn every_unusable_form_is_refused_by_name() -> TestResult {
    let long = format!("a:{}:1:0", "x".repeat(LIMIT + 1));
    let cases: Vec<(Vec<String>, IdentityRefusal)> = vec![
        (ids(&[]), IdentityRefusal::MissingId),
        (ids(&["a:b:1:0", "a:b:1:1"]), IdentityRefusal::RepeatedId),
        (ids(&["a:b:1"]), IdentityRefusal::WrongPartCount),
        (ids(&["a:b:1:0:9"]), IdentityRefusal::WrongPartCount),
        (ids(&["a:b:1:0:9:8:7"]), IdentityRefusal::WrongPartCount),
        (ids(&[""]), IdentityRefusal::WrongPartCount),
        (ids(&["b:agent:1:0"]), IdentityRefusal::WrongTenant),
        (ids(&["A:agent:1:0"]), IdentityRefusal::WrongTenant),
        (ids(&[":agent:1:0"]), IdentityRefusal::WrongTenant),
        (ids(&["a::1:0"]), IdentityRefusal::BadAgent),
        (ids(&["a:ag ent:1:0"]), IdentityRefusal::BadAgent),
        (ids(&["a:ag.ent:1:0"]), IdentityRefusal::BadAgent),
        (ids(&["a:agent\u{e9}:1:0"]), IdentityRefusal::BadAgent),
        (ids(&[long.as_str()]), IdentityRefusal::BadAgent),
        (ids(&["a:b:01:0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b:+1:0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b:-1:0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b::0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b:x:0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b:18446744073709551616:0"]), IdentityRefusal::BadSequence),
        (ids(&["a:b:1:00"]), IdentityRefusal::BadIndex),
        (ids(&["a:b:1:+0"]), IdentityRefusal::BadIndex),
        (ids(&["a:b:1:"]), IdentityRefusal::BadIndex),
        (ids(&["a:b:1: 0"]), IdentityRefusal::BadIndex),
    ];
    cases
        .iter()
        .for_each(|(values, refusal)| assert_eq!(agent_from_ids(values, "a", LIMIT), Err(*refusal), "{values:?}"));
    Ok(())
}


#[test]
fn the_pieces_have_their_own_rules() -> TestResult {
    assert_eq!(single_id(&ids(&["x"])), Ok("x"));
    assert!(is_canonical::<u64>("0") && is_canonical::<usize>("10"));
    assert!(!is_canonical::<u64>("00") && !is_canonical::<u64>("") && !is_canonical::<u64>("-0"));
    assert!(is_agent_id("a-b_C9", LIMIT) && !is_agent_id("", LIMIT) && !is_agent_id("ab", 1));
    assert_eq!(stored_time(Some(STORED)), Ok(STORED));
    assert_eq!(stored_time(None), Err(IdentityRefusal::NoStoredTime));
    let names: Vec<String> = [
        IdentityRefusal::MissingId,
        IdentityRefusal::RepeatedId,
        IdentityRefusal::WrongPartCount,
        IdentityRefusal::WrongTenant,
        IdentityRefusal::BadAgent,
        IdentityRefusal::BadSequence,
        IdentityRefusal::BadIndex,
        IdentityRefusal::NoStoredTime,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(
        names,
        [
            "no_message_id",
            "repeated_message_id",
            "wrong_part_count",
            "tenant_mismatch",
            "bad_agent_id",
            "bad_sequence",
            "bad_index",
            "no_stored_time"
        ]
    );
    Ok(())
}
