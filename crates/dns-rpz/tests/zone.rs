#[path = "common/memory.rs"]
mod memory;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use dns_rpz::model::Entry;
use dns_rpz::zone::{apply_cap, record_count, render_zone};
use memory::LimitedWriter;
use sample::sample_policy;
use types::TestResult;


const HIGH: u8 = 90;


const MEDIUM: u8 = 60;


const LOW: u8 = 30;


const SERIAL: u32 = 2_026_110_301;


const ROOM_FOR_FOUR: usize = 4;


const ROOM_FOR_TWO: usize = 2;


const DROPPED_TWO: u64 = 2;


fn entry(owner: &str, wildcard: bool, confidence: u8) -> Entry {
    Entry {
        owner: owner.to_owned(),
        wildcard,
        rdata: ".".to_owned(),
        action: "nxdomain",
        confidence,
    }
}


fn owners(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|candidate| candidate.owner.as_str()).collect()
}


#[test]
fn a_wildcard_entry_is_two_records() -> TestResult {
    assert_eq!(record_count(&entry("a.example", false, HIGH)), 1);
    assert_eq!(record_count(&entry("a.example", true, HIGH)), ROOM_FOR_TWO);
    Ok(())
}


#[test]
fn the_cap_drops_the_lowest_confidence_entries_first() -> TestResult {
    let entries = vec![
        entry("c.example", false, LOW),
        entry("a.example", false, HIGH),
        entry("d.example", false, MEDIUM),
        entry("b.example", false, MEDIUM),
    ];
    let (kept, dropped) = apply_cap(entries.clone(), ROOM_FOR_FOUR - 1);
    assert_eq!((owners(&kept), dropped), (vec!["a.example", "b.example", "d.example"], 1));
    let (everything, none) = apply_cap(entries.clone(), ROOM_FOR_FOUR);
    assert_eq!((owners(&everything), none), (vec!["a.example", "b.example", "c.example", "d.example"], 0));
    let (nothing, all) = apply_cap(entries, 0);
    assert_eq!((nothing.len(), all), (0, ROOM_FOR_FOUR as u64));
    Ok(())
}


#[test]
fn the_cap_never_splits_an_entry_and_never_skips_ahead() -> TestResult {
    let entries = vec![
        entry("a.example", false, HIGH),
        entry("b.example", true, MEDIUM),
        entry("c.example", false, LOW),
    ];
    let (kept, dropped) = apply_cap(entries, ROOM_FOR_TWO);
    assert_eq!((owners(&kept), dropped), (vec!["a.example"], DROPPED_TWO));
    Ok(())
}


#[test]
fn the_zone_is_a_master_file_with_sorted_triggers() -> TestResult {
    let mut out = Vec::new();
    let entries = vec![entry("a.example", true, HIGH), entry("32.1.0.0.10.rpz-ip", false, HIGH)];
    render_zone(&sample_policy(), SERIAL, &entries, &mut out)?;
    assert_eq!(
        String::from_utf8(out)?,
        "$ORIGIN rpz.example.org.\n\
         $TTL 300\n\
         @ IN SOA ns1.example.org. hostmaster.example.org. 2026110301 3600 600 86400 300\n\
         @ IN NS ns1.example.org.\n\
         a.example IN CNAME .\n\
         *.a.example IN CNAME .\n\
         32.1.0.0.10.rpz-ip IN CNAME .\n"
    );
    Ok(())
}


#[test]
fn a_writer_that_fails_anywhere_fails_the_render() -> TestResult {
    let policy = sample_policy();
    let entries = vec![entry("a.example", true, HIGH), entry("b.example", false, HIGH)];
    let mut full = Vec::new();
    render_zone(&policy, SERIAL, &entries, &mut full)?;
    (0..full.len()).for_each(|room| {
        let mut writer = LimitedWriter { remaining: room };
        assert!(render_zone(&policy, SERIAL, &entries, &mut writer).is_err(), "room {room}");
    });
    let mut exact = LimitedWriter { remaining: full.len() };
    render_zone(&policy, SERIAL, &entries, &mut exact)?;
    Ok(())
}
