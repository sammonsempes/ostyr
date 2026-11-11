#[path = "common/broken.rs"]
mod broken;
#[path = "common/clock.rs"]
mod clock;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/ioc.rs"]
mod ioc;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use broken::BrokenReader;
use clock::now;
use core_config::load::load_file;
use dns_rpz::error::RpzError;
use dns_rpz::model::RunSummary;
use dns_rpz::policy::{validate_policy, Policy};
use dns_rpz::run::{count, generate, open_file};
use fixtures::fixture;
use intel_feeds::limits::MAX_LINE_BYTES;
use intel_feeds::model::{Ioc, IocType, Tlp};
use ioc::ioc;
use logging::init_logging;
use sample::sample_policy;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, Cursor};
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


const HIGH: u8 = 90;


const MEDIUM: u8 = 70;


const LOW: u8 = 55;


const FIXTURE_RECORDS: u64 = 8;


const FIRST_SERIAL: u32 = 2_026_110_301;


const CAP: usize = 2;


const TWO: u64 = 2;


const FOUR: u64 = 4;


fn lines(iocs: &[Ioc]) -> Result<String, serde_json::Error> {
    iocs.iter()
        .map(|candidate| serde_json::to_string(candidate).map(|line| line + "\n"))
        .collect()
}


fn generated(policy: &Policy, input: &[u8], dir: &Path) -> Result<RunSummary, RpzError> {
    init_logging();
    generate(
        policy,
        &mut Cursor::new(input.to_vec()),
        now(),
        &dir.join("counter"),
        &dir.join("zone.db"),
    )
}


fn counts(pairs: &[(&'static str, u64)]) -> BTreeMap<&'static str, u64> {
    pairs.iter().copied().collect()
}


#[test]
fn the_fixture_iocs_give_the_snapshot_zone() -> TestResult {
    init_logging();
    let dir = tempdir()?;
    let policy = load_file::<Policy>(&fixture("policy.yaml"))?;
    validate_policy(&policy)?;
    let summary = generate(
        &policy,
        &mut open_file(&fixture("iocs.jsonl"))?,
        now(),
        &dir.path().join("counter"),
        &dir.path().join("zone.db"),
    )?;
    assert_eq!(
        fs::read_to_string(dir.path().join("zone.db"))?,
        fs::read_to_string(fixture("expected.zone"))?
    );
    assert_eq!(
        summary,
        RunSummary {
            published: counts(&[("cname", 1), ("nodata", 1), ("nxdomain", TWO), ("passthru", TWO)]),
            skipped: counts(&[
                ("allowlisted", TWO),
                ("duplicate", 1),
                ("expired", 1),
                ("invalid_name", TWO),
                ("low_confidence", 1),
                ("malformed_line", 1),
                ("tlp", 1),
                ("unsupported_type", TWO),
            ]),
            dropped_by_cap: 0,
            source_bad_rows: 0,
            records: FIXTURE_RECORDS,
            serial: FIRST_SERIAL,
        }
    );
    Ok(())
}


#[test]
fn every_run_publishes_a_higher_serial() -> TestResult {
    let dir = tempdir()?;
    let input = lines(&[ioc(IocType::Domain, "evil.example.com", HIGH, Tlp::Amber)])?;
    let first = generated(&sample_policy(), input.as_bytes(), dir.path())?;
    let second = generated(&sample_policy(), input.as_bytes(), dir.path())?;
    assert_eq!((first.serial, second.serial), (FIRST_SERIAL, FIRST_SERIAL + 1));
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains(&format!("{} ", FIRST_SERIAL + 1)));
    Ok(())
}


#[test]
fn the_cap_keeps_the_most_confident_entries_and_counts_the_rest() -> TestResult {
    let dir = tempdir()?;
    let mut policy = sample_policy();
    policy.wildcard = false;
    policy.max_records = CAP;
    let input = lines(&[
        ioc(IocType::Domain, "low.example.com", LOW, Tlp::Amber),
        ioc(IocType::Domain, "high.example.com", HIGH, Tlp::Amber),
        ioc(IocType::Domain, "medium.example.com", MEDIUM, Tlp::Amber),
    ])?;
    let summary = generated(&policy, input.as_bytes(), dir.path())?;
    let zone = fs::read_to_string(dir.path().join("zone.db"))?;
    assert_eq!((summary.dropped_by_cap, summary.records), (1, CAP as u64));
    assert!(zone.contains("high.example.com IN CNAME .\n") && zone.contains("medium.example.com IN CNAME .\n"));
    assert!(!zone.contains("low.example.com"));
    Ok(())
}


#[test]
fn the_more_confident_duplicate_stays_whatever_the_order() -> TestResult {
    let dir = tempdir()?;
    let strong = ioc(IocType::Ipv4, "192.0.2.1", HIGH, Tlp::Amber);
    let weak = ioc(IocType::Cidr, "192.0.2.1/32", MEDIUM, Tlp::Amber);
    let mut policy = sample_policy();
    policy.actions.cidr.action = dns_rpz::policy::Action::Nodata;
    generated(&policy, lines(&[strong.clone(), weak.clone()])?.as_bytes(), dir.path())?;
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains("32.1.2.0.192.rpz-ip IN CNAME .\n"));
    let summary = generated(&policy, lines(&[weak, strong])?.as_bytes(), dir.path())?;
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains("32.1.2.0.192.rpz-ip IN CNAME .\n"));
    assert_eq!(summary.skipped, counts(&[("duplicate", 1)]));
    Ok(())
}


#[test]
fn unreadable_lines_are_counted_and_do_not_stop_the_run() -> TestResult {
    let dir = tempdir()?;
    let valid = lines(&[ioc(IocType::Domain, "evil.example.com", HIGH, Tlp::Amber)])?;
    let mut input = valid.into_bytes();
    input.extend_from_slice(b"\n   \n\xff\xfe\n{\"ioc_type\":\"domain\"}\n");
    input.extend(std::iter::repeat_n(b'a', MAX_LINE_BYTES + 1));
    input.extend_from_slice(b"\nlast line without newline");
    let summary = generated(&sample_policy(), &input, dir.path())?;
    assert_eq!(summary.skipped, counts(&[("malformed_line", FOUR)]));
    assert_eq!(summary.published, counts(&[("nxdomain", 1)]));
    Ok(())
}


#[test]
fn a_failing_input_stops_the_run_before_anything_is_written() -> TestResult {
    init_logging();
    let dir = tempdir()?;
    let result = generate(
        &sample_policy(),
        &mut BufReader::new(BrokenReader),
        now(),
        &dir.path().join("counter"),
        &dir.path().join("zone.db"),
    );
    assert!(matches!(result, Err(RpzError::Io(_))));
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    Ok(())
}


#[test]
fn a_bad_counter_stops_the_run_and_keeps_the_previous_zone() -> TestResult {
    let dir = tempdir()?;
    fs::write(dir.path().join("zone.db"), "previous\n")?;
    fs::write(dir.path().join("counter"), "garbage\n")?;
    let result = generated(&sample_policy(), b"", dir.path());
    assert!(matches!(result, Err(RpzError::Serial(_))));
    assert_eq!(fs::read_to_string(dir.path().join("zone.db"))?, "previous\n");
    Ok(())
}


#[test]
fn a_zone_that_cannot_be_written_is_an_error() -> TestResult {
    init_logging();
    let dir = tempdir()?;
    let result = generate(
        &sample_policy(),
        &mut Cursor::new(Vec::new()),
        now(),
        &dir.path().join("counter"),
        &dir.path().join("missing").join("zone.db"),
    );
    assert!(matches!(result, Err(RpzError::Io(_))));
    Ok(())
}


#[test]
fn an_invalid_allowlist_is_a_policy_error() -> TestResult {
    let dir = tempdir()?;
    let mut policy = sample_policy();
    policy.allowlist.cidrs.push("10.0.0.0/33".to_owned());
    assert!(matches!(generated(&policy, b"", dir.path()), Err(RpzError::Policy(_))));
    Ok(())
}


#[test]
fn counting_and_opening_files() -> TestResult {
    let mut tally = BTreeMap::new();
    count(&mut tally, "a");
    count(&mut tally, "a");
    assert_eq!(tally, counts(&[("a", TWO)]));
    assert!(open_file(Path::new("/nonexistent/iocs.jsonl")).is_err());
    Ok(())
}
