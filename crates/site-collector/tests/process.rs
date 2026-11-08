#[path = "support/types.rs"]
mod types;


use site_collector::admission::{new_collector, source_counters};
use site_collector::error::ParseError;
use site_collector::model::{BucketLimits, CollectorConfig, DropReason, Outcome, MAX_MESSAGE_BYTES};
use site_collector::process::process_datagram;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use types::TestResult;


const YEAR: i32 = 2003;


const RATE: u64 = 100;


const SHARE: u64 = 99;


const UNKNOWN_SHARE: u64 = 20;


const MAX_SOURCES: usize = 4;


const LINE: &str = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - hello";


#[test]
fn outcomes_are_counted_per_source() -> TestResult {
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let config = CollectorConfig {
        global: BucketLimits {
            rate_per_second: RATE,
            burst: RATE,
        },
        source_share_percent: SHARE,
        unknown_share_percent: UNKNOWN_SHARE,
        sources: BTreeSet::from([source]),
        drop_unknown: true,
        max_sources: MAX_SOURCES,
    };
    let mut state = new_collector(config)?;
    let accepted = process_datagram(&mut state, source, LINE.as_bytes(), 0, YEAR);
    assert!(matches!(accepted, Outcome::Accepted(ref record) if record.message == "hello"));
    let malformed = process_datagram(&mut state, source, b"garbage", 0, YEAR);
    assert!(matches!(malformed, Outcome::Malformed(ParseError::Malformed)));
    let oversized = vec![b'a'; MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        process_datagram(&mut state, source, &oversized, 0, YEAR),
        Outcome::Dropped(DropReason::TooLarge)
    );
    let counters = source_counters(&state, &source).ok_or("tracked")?;
    assert_eq!((counters.accepted, counters.parse_errors, counters.dropped_size), (1, 1, 1));
    Ok(())
}
