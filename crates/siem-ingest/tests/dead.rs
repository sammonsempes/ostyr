use serde_json::error::Category;
use siem_ingest::dead::{
    category_of, class_of_reason, class_text, groups_text, log_dead_groups, log_summary, record_dead_letter, summary_due, MAX_DEAD_LETTER_GROUPS,
    SUMMARY_SECONDS,
};
use siem_ingest::model::{DeadGroups, DeadLetterClass, LoopReport};
use siem_ingest::parse::check_message;
use siem_ingest::pipeline::POISON_REASON;
use siem_ingest::tenant::{dead_letter_subject, dead_letter_token, INVALID_TENANT_TOKEN};
use std::error::Error;
use time::OffsetDateTime;


const PREFIX: &str = "dead.events";


const MAX_TENANT: usize = 64;


const EXTRA_GROUPS: usize = 5;


const SMALL_CAP: usize = 3;


const LARGE_CAP: usize = 100;


const START: i64 = 1_800_000_000;


const TWICE: u64 = 2;


fn reason_of(payload: &[u8], cap: usize) -> Result<String, Box<dyn Error>> {
    check_message(payload, cap).err().ok_or_else(|| "the message was accepted".into())
}


#[test]
fn every_class_has_a_fixed_text() -> Result<(), Box<dyn Error>> {
    assert_eq!(class_text(&DeadLetterClass::Oversize), "oversize");
    assert_eq!(class_text(&DeadLetterClass::NotEcs(Category::Syntax)), "not_ecs:Syntax");
    assert_eq!(class_text(&DeadLetterClass::Poison), "poison");
    assert_eq!(
        class_text(&DeadLetterClass::Identity("bad_agent_id".to_owned())),
        "identity_unusable:bad_agent_id"
    );
    assert_eq!(class_text(&DeadLetterClass::Other), "other");
    Ok(())
}


#[test]
fn the_class_of_a_reason_comes_from_what_check_message_wrote() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        class_of_reason(&reason_of(b"not json", LARGE_CAP)?),
        DeadLetterClass::NotEcs(Category::Syntax)
    );
    assert_eq!(class_of_reason(&reason_of(b"", LARGE_CAP)?), DeadLetterClass::NotEcs(Category::Eof));
    assert_eq!(class_of_reason(&reason_of(b"{}", LARGE_CAP)?), DeadLetterClass::NotEcs(Category::Data));
    assert_eq!(class_of_reason(&reason_of(b"0123456789", SMALL_CAP)?), DeadLetterClass::Oversize);
    assert_eq!(class_of_reason(POISON_REASON), DeadLetterClass::Poison);
    assert_eq!(class_of_reason("anything else"), DeadLetterClass::Other);
    assert_eq!(category_of("Io error at line 1"), Category::Io);
    Ok(())
}


#[test]
fn groups_are_capped_and_the_rest_counted() -> Result<(), Box<dyn Error>> {
    let mut groups = DeadGroups::default();
    (0..MAX_DEAD_LETTER_GROUPS + EXTRA_GROUPS).for_each(|index| record_dead_letter(&mut groups, &format!("t{index}"), &DeadLetterClass::Poison));
    assert_eq!(groups.groups.len(), MAX_DEAD_LETTER_GROUPS);
    assert_eq!(groups.other_groups, EXTRA_GROUPS as u64);
    record_dead_letter(&mut groups, "t0", &DeadLetterClass::Poison);
    assert_eq!(groups.groups.get(&("t0".to_owned(), "poison".to_owned())), Some(&TWICE));
    assert_eq!(groups.other_groups, EXTRA_GROUPS as u64);
    Ok(())
}


#[test]
fn the_group_text_names_tenant_class_and_count_and_the_record_is_emptied() -> Result<(), Box<dyn Error>> {
    let mut groups = DeadGroups::default();
    record_dead_letter(&mut groups, "a", &DeadLetterClass::Oversize);
    record_dead_letter(&mut groups, "a", &DeadLetterClass::Oversize);
    record_dead_letter(&mut groups, "b", &DeadLetterClass::Poison);
    assert_eq!(groups_text(&groups), "a/oversize=2 b/poison=1");
    log_dead_groups(&mut groups);
    assert_eq!(groups, DeadGroups::default());
    log_dead_groups(&mut groups);
    assert_eq!(groups, DeadGroups::default());
    Ok(())
}


#[test]
fn the_summary_is_due_exactly_at_the_period() -> Result<(), Box<dyn Error>> {
    let start = OffsetDateTime::from_unix_timestamp(START)?;
    assert!(!summary_due(start, start + time::Duration::seconds(SUMMARY_SECONDS - 1)));
    assert!(summary_due(start, start + time::Duration::seconds(SUMMARY_SECONDS)));
    log_summary(&LoopReport::default());
    Ok(())
}


#[test]
fn the_dead_letter_subject_is_always_one_checked_token() -> Result<(), Box<dyn Error>> {
    assert_eq!(dead_letter_subject(PREFIX, "tenant-a", MAX_TENANT), "dead.events.tenant-a");
    ["", "a.b", "*", ">", "-x", "a b", "a\nb"].iter().for_each(|tenant| {
        assert_eq!(dead_letter_subject(PREFIX, tenant, MAX_TENANT), "dead.events._invalid", "{tenant:?}");
        assert_eq!(dead_letter_token(tenant, MAX_TENANT), INVALID_TENANT_TOKEN);
    });
    let long = "a".repeat(MAX_TENANT + 1);
    assert_eq!(dead_letter_token(&long, MAX_TENANT), INVALID_TENANT_TOKEN);
    assert_eq!(dead_letter_token(&long, MAX_TENANT + 1), INVALID_TENANT_TOKEN);
    assert_eq!(dead_letter_token("tenant-a", SMALL_CAP), INVALID_TENANT_TOKEN);
    Ok(())
}
