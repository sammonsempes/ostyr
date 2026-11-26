#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use dhcp_kea::follow::Counts;
use dhcp_kea::header::parse_header;
use dhcp_kea::row::convert_row;
use dhcp_kea::serve::{counts_delta, log_counts, log_waiting_at_stop, Follower};
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::TestResult;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


const COUNTS_LINE: &str = "dhcp round counts";


const ABSENT_LINE: &str = "the lease file is absent";


const TWO: u64 = 2;


const THREE: u64 = 3;


const FOUR: u64 = 4;


const FIVE: u64 = 5;


const SIX: u64 = 6;


const SEVEN: u64 = 7;


const EIGHT: u64 = 8;


const NINE: u64 = 9;


struct Shared(Arc<Mutex<Vec<u8>>>);


impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poisoned| std::io::Error::other("poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn captured(delta: &Counts) -> Result<String, Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Shared(Arc::clone(&writer)))
            .finish(),
    );
    tracing::dispatcher::with_default(&dispatch, || log_counts(delta));
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok(String::from_utf8(bytes)?)
}


fn with_one(set: fn(&mut Counts)) -> Counts {
    let mut counts = Counts::default();
    set(&mut counts);
    counts
}


#[test]
fn an_absent_lease_file_warns_every_round_with_fixed_text() -> TestResult {
    let absent = with_one(|counts| counts.absent = 1);
    let first = captured(&absent)?;
    let second = captured(&absent)?;
    assert!(first.contains("WARN") && first.contains(ABSENT_LINE), "{first}");
    assert!(second.contains("WARN") && second.contains(ABSENT_LINE), "{second}");
    assert!(!first.contains(COUNTS_LINE));
    Ok(())
}


#[test]
fn a_quiet_round_logs_nothing() -> TestResult {
    assert_eq!(captured(&Counts::default())?, "");
    Ok(())
}


#[test]
fn every_count_is_a_named_field_of_the_round_warning() -> TestResult {
    let named = [
        ("refused=2", with_one(|counts| counts.refused = TWO)),
        ("evicted=3", with_one(|counts| counts.evicted = THREE)),
        ("unrecovered=4", with_one(|counts| counts.unrecovered = FOUR)),
        ("beyond_seen=5", with_one(|counts| counts.beyond_seen = FIVE)),
        ("restarts=6", with_one(|counts| counts.restarts = SIX)),
    ];
    named.iter().try_for_each(|(expected, delta)| {
        let text = captured(delta)?;
        assert!(
            text.contains("WARN") && text.contains(COUNTS_LINE) && text.contains(expected),
            "{expected}: {text}"
        );
        assert!(!text.contains(ABSENT_LINE));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn malformed_kinds_alone_raise_the_warning_and_are_named() -> TestResult {
    let mut delta = Counts::default();
    delta.malformed.insert("address".to_owned(), TWO);
    delta.malformed.insert("not-utf8".to_owned(), 1);
    let text = captured(&delta)?;
    assert!(text.contains(COUNTS_LINE) && text.contains("address=2,not-utf8=1"), "{text}");
    Ok(())
}


#[test]
fn the_delta_of_a_round_is_what_it_added_for_every_count() -> TestResult {
    let mut before = Counts {
        evicted: 1,
        restarts: 1,
        absent: 1,
        refused: 1,
        unrecovered: 1,
        beyond_seen: 1,
        processed: NINE,
        ..Counts::default()
    };
    before.malformed.insert("address".to_owned(), 1);
    before.malformed.insert("state".to_owned(), FOUR);
    let mut after = Counts {
        evicted: THREE,
        restarts: FOUR,
        absent: FIVE,
        refused: SIX,
        unrecovered: SEVEN,
        beyond_seen: EIGHT,
        processed: NINE + NINE,
        ..Counts::default()
    };
    after.malformed.insert("address".to_owned(), THREE);
    after.malformed.insert("state".to_owned(), FOUR);
    after.malformed.insert("not-utf8".to_owned(), TWO);
    let delta = counts_delta(&before, &after);
    assert_eq!(
        (
            delta.evicted,
            delta.restarts,
            delta.absent,
            delta.refused,
            delta.unrecovered,
            delta.beyond_seen
        ),
        (TWO, THREE, FOUR, FIVE, SIX, SEVEN)
    );
    assert_eq!(delta.processed, 0);
    assert_eq!(delta.malformed.len() as u64, TWO);
    assert_eq!(delta.malformed.get("address"), Some(&TWO));
    assert_eq!(delta.malformed.get("not-utf8"), Some(&TWO));
    assert_eq!(counts_delta(&after, &after), Counts::default());
    Ok(())
}


const LEASE_HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


fn captured_stop(follower: &Follower) -> Result<String, Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Shared(Arc::clone(&writer)))
            .finish(),
    );
    tracing::dispatcher::with_default(&dispatch, || log_waiting_at_stop(follower));
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok(String::from_utf8(bytes)?)
}


#[test]
fn stopping_with_waiting_macs_logs_how_many_are_dropped_and_an_empty_list_logs_nothing() -> TestResult {
    let lease = convert_row(&parse_header(LEASE_HEADER)?, "10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,,0,")?;
    let waiting = Follower {
        waiting: vec![lease.clone(), lease],
        ..Follower::default()
    };
    let text = captured_stop(&waiting)?;
    assert!(text.contains("WARN") && text.contains("waiting=2") && text.contains("dropped"), "{text}");
    assert_eq!(captured_stop(&Follower::default())?, "");
    Ok(())
}
