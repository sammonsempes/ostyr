use hunt_stats::beacon::beaconing;
use hunt_stats::error::StatsError;
use hunt_stats::input::{parse_observations, parse_timestamps, read_bounded};
use hunt_stats::model::{BeaconLimits, KeyEntities, KeyReport, StackLimits};
use hunt_stats::render::{write_beacon, write_key_report};
use hunt_stats::stack::rare_keys;
use std::io::{Error, Read, Write};


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::other("read failed"))
    }
}


impl Write for Broken {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(Error::other("write failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


const FOUR: u64 = 4;


const TWO: usize = 2;


const THREE: usize = 3;


const TEN: i64 = 10;


const NEGATIVE: i64 = -2;


const MINUTE: i64 = 60;


#[test]
fn read_bounded_accepts_exact_limit_and_refuses_more() -> Result<(), StatsError> {
    assert_eq!(read_bounded(&mut "abcd".as_bytes(), FOUR)?, "abcd");
    assert!(matches!(
        read_bounded(&mut "abcde".as_bytes(), FOUR),
        Err(StatsError::InputTooLarge { max: FOUR })
    ));
    assert!(matches!(read_bounded(&mut Broken, FOUR), Err(StatsError::Io(_))));
    Ok(())
}


#[test]
fn observations_split_on_the_first_comma() -> Result<(), StatsError> {
    let rows = parse_observations("root,sshd\n\nbob,a,b\n")?;
    assert_eq!(
        rows,
        vec![("root".to_string(), "sshd".to_string()), ("bob".to_string(), "a,b".to_string())]
    );
    assert!(matches!(parse_observations("ok,1\nnocomma\n"), Err(StatsError::BadLine { line: TWO })));
    Ok(())
}


#[test]
fn timestamps_parse_and_report_the_line() -> Result<(), StatsError> {
    assert_eq!(parse_timestamps("1\n\n -2 \n")?, vec![1, NEGATIVE]);
    assert!(matches!(parse_timestamps("1\nx\n"), Err(StatsError::BadTimestamp { line: TWO, .. })));
    Ok(())
}


#[test]
fn key_report_is_rendered_with_the_dropped_counter() -> Result<(), StatsError> {
    let report = KeyReport {
        keys: vec![KeyEntities {
            key: "sshd".to_string(),
            entities: TWO,
            examples: vec!["a".to_string(), "b".to_string()],
        }],
        rows_dropped: THREE,
    };
    let mut out = Vec::new();
    write_key_report(&report, &mut out)?;
    assert_eq!(String::from_utf8_lossy(&out), "2\tsshd\ta,b\nrows_dropped=3\n");
    assert!(matches!(write_key_report(&report, &mut Broken), Err(StatsError::Io(_))));
    let empty = KeyReport {
        keys: Vec::new(),
        rows_dropped: 0,
    };
    assert!(matches!(write_key_report(&empty, &mut Broken), Err(StatsError::Io(_))));
    Ok(())
}


#[test]
fn beacon_is_rendered_or_none() -> Result<(), StatsError> {
    let times: Vec<i64> = (0..TEN).map(|index| index * MINUTE).collect();
    let found = beaconing(&times, &BeaconLimits::default())?;
    let mut out = Vec::new();
    write_beacon(found.as_ref(), &mut out)?;
    assert_eq!(
        String::from_utf8_lossy(&out),
        "events=10 median_interval=60 mad=0 regularity_ppm=1000000\n"
    );
    let mut none = Vec::new();
    write_beacon(None, &mut none)?;
    assert_eq!(String::from_utf8_lossy(&none), "none\n");
    assert!(matches!(write_beacon(None, &mut Broken), Err(StatsError::Io(_))));
    assert!(matches!(write_beacon(found.as_ref(), &mut Broken), Err(StatsError::Io(_))));
    Ok(())
}


#[test]
fn rare_keys_on_parsed_rows() -> Result<(), StatsError> {
    let rows = parse_observations("a,x\nb,x\na,y\n")?;
    let report = rare_keys(&rows, 1, &StackLimits::default())?;
    assert_eq!(report.keys.len(), 1);
    Ok(())
}
