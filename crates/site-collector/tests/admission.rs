#[path = "support/types.rs"]
mod types;


use site_collector::admission::{
    admit, collector_config, is_tracked, new_collector, prune_idle, reconfigure, share_limits, source_counters, take_token, tracked_sources,
    untracked_dropped, validate_config,
};
use site_collector::error::ConfigError;
use site_collector::model::{
    Bucket, BucketLimits, Collector, CollectorConfig, DropReason, ScaledLimits, MAX_MESSAGE_BYTES, MAX_UNKNOWN_SHARE_PERCENT, UNITS_PER_TOKEN,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use types::TestResult;


const GLOBAL_RATE: u64 = 10;


const GLOBAL_BURST: u64 = 10;


const SHARE: u64 = 50;


const UNKNOWN_SHARE: u64 = 50;


const STORM_RATE: u64 = 1000;


const STORM_SHARE: u64 = 10;


const STORM_SOURCES: u16 = 1000;


const STORM_STEPS: u64 = 100;


const STEP_MS: u64 = 10;


const STORM_PER_STEP: u16 = 200;


const STORM_TABLE: usize = 1024;


const ADDRESS_SPAN: u16 = 250;


const MAX_SOURCES: usize = 3;


const MILLIS_PER_SECOND: u64 = 1000;


const HALF_SECOND: u64 = 500;


const FULL_SHARE: u64 = 100;


const EXACT_BURST: u64 = 100;


const EXACT_SHARE: u64 = 5;


const TWO: u64 = 2;


const TINY_STEPS: u64 = 10;


const TINY_SPOOFED: u8 = 20;


const TINY_TABLE: usize = 32;


const IDLE: u64 = 100;


const NET: u8 = 10;


const HOST_A: u8 = 1;


const HOST_B: u8 = 2;


const HOST_C: u8 = 3;


const SOURCE_TOKENS: u64 = 5;


const BUCKET_RATE: u64 = 2;


const SPOOFED: u8 = 5;


const SPOOF_BASE: u8 = 100;


const FLOOD: usize = 50;


fn host(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(NET, 0, 0, last))
}


fn config(declared: &[u8], drop_unknown: bool) -> CollectorConfig {
    CollectorConfig {
        global: BucketLimits {
            rate_per_second: GLOBAL_RATE,
            burst: GLOBAL_BURST,
        },
        source_share_percent: SHARE,
        unknown_share_percent: UNKNOWN_SHARE,
        sources: declared.iter().map(|last| host(*last)).collect::<BTreeSet<_>>(),
        drop_unknown,
        max_sources: MAX_SOURCES,
    }
}


fn collector(declared: &[u8], drop_unknown: bool) -> Result<Collector, ConfigError> {
    new_collector(config(declared, drop_unknown))
}


#[test]
fn invalid_configs_are_refused() -> TestResult {
    let mut bad = config(&[], false);
    bad.global.rate_per_second = 0;
    assert_eq!(validate_config(&bad), Err(ConfigError::ZeroRate));
    let mut no_burst = config(&[], false);
    no_burst.global.burst = 0;
    assert_eq!(validate_config(&no_burst), Err(ConfigError::ZeroBurst));
    let mut no_share = config(&[], false);
    no_share.source_share_percent = 0;
    assert_eq!(validate_config(&no_share), Err(ConfigError::BadShare));
    no_share.source_share_percent = FULL_SHARE;
    assert_eq!(validate_config(&no_share), Err(ConfigError::BadShare));
    let mut no_unknown = config(&[], false);
    no_unknown.unknown_share_percent = 0;
    assert_eq!(validate_config(&no_unknown), Err(ConfigError::BadUnknownShare));
    no_unknown.unknown_share_percent = FULL_SHARE;
    assert_eq!(validate_config(&no_unknown), Err(ConfigError::BadUnknownShare));
    no_unknown.unknown_share_percent = MAX_UNKNOWN_SHARE_PERCENT + 1;
    assert_eq!(validate_config(&no_unknown), Err(ConfigError::BadUnknownShare));
    no_unknown.unknown_share_percent = MAX_UNKNOWN_SHARE_PERCENT;
    assert_eq!(validate_config(&no_unknown), Ok(()));
    let mut sub_message = config(&[], false);
    sub_message.global.burst = 1;
    assert_eq!(validate_config(&sub_message), Err(ConfigError::ShareBelowOneMessage));
    let mut sub_unknown = config(&[], false);
    sub_unknown.unknown_share_percent = 1;
    assert_eq!(validate_config(&sub_unknown), Err(ConfigError::ShareBelowOneMessage));
    let mut no_sources = config(&[], false);
    no_sources.max_sources = 0;
    assert_eq!(new_collector(no_sources).err(), Some(ConfigError::ZeroMaxSources));
    assert_eq!(validate_config(&config(&[], false)), Ok(()));
    Ok(())
}


#[test]
fn share_is_an_exact_fraction_never_rounded_up() -> TestResult {
    let global = BucketLimits {
        rate_per_second: GLOBAL_RATE,
        burst: EXACT_BURST,
    };
    let limits = share_limits(&global, EXACT_SHARE);
    assert_eq!(
        limits,
        ScaledLimits {
            rate_per_ms: GLOBAL_RATE * EXACT_SHARE,
            burst: EXACT_SHARE * UNITS_PER_TOKEN
        }
    );
    let mut bucket = Bucket {
        units: limits.burst,
        updated_ms: 0,
    };
    let taken = (0..EXACT_BURST).filter(|_| take_token(&mut bucket, &limits, 0)).count();
    assert_eq!(taken as u64, EXACT_SHARE);
    assert!(!take_token(&mut bucket, &limits, 0));
    assert!(!take_token(&mut bucket, &limits, MILLIS_PER_SECOND));
    assert!(take_token(&mut bucket, &limits, MILLIS_PER_SECOND * TWO));
    Ok(())
}


#[test]
fn bucket_refills_with_the_injected_clock_and_caps_at_burst() -> TestResult {
    let limits = share_limits(
        &BucketLimits {
            rate_per_second: BUCKET_RATE,
            burst: BUCKET_RATE,
        },
        FULL_SHARE,
    );
    let mut bucket = Bucket { units: 0, updated_ms: 0 };
    assert!(!take_token(&mut bucket, &limits, 0));
    assert!(take_token(&mut bucket, &limits, HALF_SECOND));
    assert!(!take_token(&mut bucket, &limits, HALF_SECOND));
    assert!(take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(!take_token(&mut bucket, &limits, MILLIS_PER_SECOND * MILLIS_PER_SECOND));
    assert!(!take_token(&mut bucket, &limits, 0));
    Ok(())
}


#[test]
fn size_cap_drops_and_counts() -> TestResult {
    let mut state = collector(&[HOST_A], true)?;
    assert_eq!(admit(&mut state, host(HOST_A), MAX_MESSAGE_BYTES, 0), Ok(()));
    assert_eq!(admit(&mut state, host(HOST_A), MAX_MESSAGE_BYTES + 1, 0), Err(DropReason::TooLarge));
    let counters = source_counters(&state, &host(HOST_A)).ok_or("tracked")?;
    assert_eq!(counters.dropped_size, 1);
    assert_eq!(counters.unknown_seen, 0);
    Ok(())
}


#[test]
fn unknown_sources_are_counted_and_dropped_on_request() -> TestResult {
    let mut dropping = collector(&[HOST_A], true)?;
    assert_eq!(admit(&mut dropping, host(HOST_B), 1, 0), Err(DropReason::UnknownSource));
    let counters = source_counters(&dropping, &host(HOST_B)).ok_or("tracked")?;
    assert_eq!((counters.unknown_seen, counters.dropped_unknown), (1, 1));
    let mut lenient = collector(&[HOST_A], false)?;
    assert_eq!(admit(&mut lenient, host(HOST_B), 1, 0), Ok(()));
    let lenient_counters = source_counters(&lenient, &host(HOST_B)).ok_or("tracked")?;
    assert_eq!((lenient_counters.unknown_seen, lenient_counters.dropped_unknown), (1, 0));
    Ok(())
}


#[test]
fn flooding_source_does_not_starve_another() -> TestResult {
    let mut state = collector(&[HOST_A, HOST_B], true)?;
    let flood_results: Vec<_> = (0..FLOOD).map(|_| admit(&mut state, host(HOST_A), 1, 0)).collect();
    let admitted = flood_results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(admitted as u64, SOURCE_TOKENS);
    assert!(flood_results.contains(&Err(DropReason::SourceRate)));
    assert_eq!(admit(&mut state, host(HOST_B), 1, 0), Ok(()));
    let flooder = source_counters(&state, &host(HOST_A)).ok_or("tracked")?;
    assert_eq!(flooder.dropped_rate, FLOOD as u64 - SOURCE_TOKENS);
    Ok(())
}


#[test]
fn global_bucket_caps_the_total() -> TestResult {
    let mut state = collector(&[HOST_A, HOST_B, HOST_C], true)?;
    let results: Vec<_> = [HOST_A, HOST_B, HOST_C]
        .iter()
        .flat_map(|last| (0..SHARE).map(move |_| *last))
        .map(|last| admit(&mut state, host(last), 1, 0))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count() as u64, GLOBAL_BURST);
    assert!(results.contains(&Err(DropReason::GlobalRate)));
    Ok(())
}


#[test]
fn distinct_source_cap_drops_new_unknown_sources_only() -> TestResult {
    let mut state = collector(&[HOST_A], false)?;
    let spoofed: Vec<_> = (0..SPOOFED).map(|offset| admit(&mut state, host(SPOOF_BASE + offset), 1, 0)).collect();
    assert_eq!(tracked_sources(&state), MAX_SOURCES);
    assert_eq!(
        spoofed.iter().filter(|result| **result == Err(DropReason::SourceTableFull)).count(),
        usize::from(SPOOFED) - MAX_SOURCES
    );
    assert_eq!(untracked_dropped(&state), (usize::from(SPOOFED) - MAX_SOURCES) as u64);
    assert_eq!(admit(&mut state, host(HOST_A), 1, 0), Ok(()));
    assert_eq!(admit(&mut state, host(SPOOF_BASE), 1, 0), Ok(()));
    assert_eq!(tracked_sources(&state), MAX_SOURCES + 1);
    Ok(())
}


#[test]
fn idle_unknown_sources_are_pruned_declared_ones_stay() -> TestResult {
    let mut state = collector(&[HOST_A], false)?;
    admit(&mut state, host(HOST_A), 1, 0)?;
    admit(&mut state, host(HOST_B), 1, 0)?;
    admit(&mut state, host(HOST_C), 1, IDLE)?;
    assert_eq!(prune_idle(&mut state, IDLE, IDLE), 1);
    assert!(is_tracked(&state, &host(HOST_A)));
    assert!(!is_tracked(&state, &host(HOST_B)));
    assert!(is_tracked(&state, &host(HOST_C)));
    Ok(())
}


#[test]
fn undeclared_sources_together_cannot_starve_a_declared_one() -> TestResult {
    let mut storm = config(&[HOST_A], false);
    storm.global = BucketLimits {
        rate_per_second: STORM_RATE,
        burst: STORM_RATE,
    };
    storm.source_share_percent = STORM_SHARE;
    storm.unknown_share_percent = STORM_SHARE;
    storm.max_sources = STORM_TABLE;
    let mut state = new_collector(storm)?;
    let declared_accepted = (0..STORM_STEPS)
        .filter(|step| {
            let now = step * STEP_MS;
            let spoofed_accepted = (0..STORM_PER_STEP)
                .filter(|position| {
                    let index = position * (STORM_SOURCES / STORM_PER_STEP);
                    let spoofed = IpAddr::V4(Ipv4Addr::new(NET, 1, (index / ADDRESS_SPAN) as u8, (index % ADDRESS_SPAN) as u8));
                    admit(&mut state, spoofed, 1, now).is_ok()
                })
                .count();
            assert!(spoofed_accepted < usize::from(STORM_PER_STEP));
            admit(&mut state, host(HOST_A), 1, now).is_ok()
        })
        .count();
    assert_eq!(declared_accepted as u64, STORM_STEPS);
    Ok(())
}


#[test]
fn undeclared_combined_bucket_reports_its_own_reason() -> TestResult {
    let mut tight = config(&[HOST_A], false);
    tight.unknown_share_percent = 1;
    tight.global.burst = EXACT_BURST;
    tight.global.rate_per_second = EXACT_BURST;
    tight.max_sources = usize::from(SPOOFED);
    let mut state = new_collector(tight)?;
    let verdicts: Vec<_> = (0..SPOOFED).map(|offset| admit(&mut state, host(SPOOF_BASE + offset), 1, 0)).collect();
    assert_eq!(verdicts.first(), Some(&Ok(())));
    assert_eq!(verdicts.get(1), Some(&Err(DropReason::UnknownRate)));
    assert_eq!(admit(&mut state, host(HOST_A), 1, 0), Ok(()));
    let counters = source_counters(&state, &host(SPOOF_BASE + 1)).ok_or("tracked")?;
    assert_eq!(counters.dropped_rate, 1);
    Ok(())
}


#[test]
fn reconfigure_validates_and_applies_new_limits() -> TestResult {
    let mut state = collector(&[HOST_A], true)?;
    let mut bad = config(&[HOST_A], true);
    bad.source_share_percent = FULL_SHARE;
    assert_eq!(reconfigure(&mut state, bad), Err(ConfigError::BadShare));
    assert_eq!(collector_config(&state).source_share_percent, SHARE);
    let mut next = config(&[HOST_B], true);
    next.max_sources = MAX_SOURCES + 1;
    reconfigure(&mut state, next.clone())?;
    assert_eq!(collector_config(&state), &next);
    assert_eq!(admit(&mut state, host(HOST_A), 1, 0), Err(DropReason::UnknownSource));
    Ok(())
}


#[test]
fn rounding_cannot_turn_a_share_into_the_whole_capacity() -> TestResult {
    let mut tiny = config(&[HOST_A], false);
    tiny.global = BucketLimits {
        rate_per_second: TWO,
        burst: TWO,
    };
    tiny.source_share_percent = MAX_UNKNOWN_SHARE_PERCENT;
    tiny.unknown_share_percent = MAX_UNKNOWN_SHARE_PERCENT;
    tiny.max_sources = TINY_TABLE;
    let mut state = new_collector(tiny)?;
    let declared_accepted = (0..TINY_STEPS)
        .filter(|step| {
            let now = step * MILLIS_PER_SECOND;
            let spoofed_accepted = (0..TINY_SPOOFED)
                .filter(|offset| admit(&mut state, host(SPOOF_BASE + offset), 1, now).is_ok())
                .count();
            assert_eq!(spoofed_accepted, 1);
            admit(&mut state, host(HOST_A), 1, now).is_ok()
        })
        .count();
    assert_eq!(declared_accepted as u64, TINY_STEPS);
    Ok(())
}
