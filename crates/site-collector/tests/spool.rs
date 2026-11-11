#[path = "support/types.rs"]
mod types;


use site_collector::dirfs::{directory_facts, open_directory, regular_file_names};
use site_collector::error::SpoolError;
use site_collector::frame::encode_frame;
use site_collector::spool::{
    acknowledge, append, append_with, check_config, check_directory, open_spool, parse_segment_name, read_from, scan_segment,
};
use site_collector::spool::{segment_path, spool_stats};
use site_collector::spool_model::{
    DirectoryFacts, Priority, Record, Spool, SpoolConfig, FRAME_HEADER_BYTES, MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES, MAX_SEGMENTS_IN_TOTAL,
    MAX_SEGMENT_BYTES, MAX_SEGMENT_FILES,
};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const SEGMENT: u64 = MAX_FRAME_BYTES;


const MIXED_CYCLES: u64 = 6000;


const EXTRA_SEGMENTS: u64 = 500;


const APPENDS_PER_CYCLE: u64 = 2;


const TOTAL: u64 = MAX_FRAME_BYTES * 3;


const PAYLOAD: usize = 1000;


const FRAME: u64 = 1017;


const ALL: usize = 1000;


const SEGMENT_FRAMES: u64 = 4;


const DOUBLE_SEGMENT_FRAMES: u64 = 8;


const TOTAL_FRAMES: u64 = 12;


const OVER_TOTAL_FRAMES: u64 = 13;


const FEW: u64 = 3;


const SOME: u64 = 6;


const REPLAYED: u64 = 10;


const FLOOD: u64 = 60;


const STALLED: u64 = 100;


const BIG_TOTAL_FACTOR: u64 = 4;


const BIG_FILL: u64 = 16;


const HALF_ACK: u64 = 7;


const PARTIAL_ACK: u64 = 2;


const LIMIT: usize = 3;


#[cfg(unix)]
const WORLD_WRITABLE: u32 = 0o777;


#[cfg(unix)]
const PRIVATE: u32 = 0o700;


const CUT_PAYLOAD_BYTES: usize = 500;


const LEN_FIELD_BYTES: usize = 4;


const ZERO_BODY_BYTES: usize = 40;


const WRONG_SEQUENCE: u64 = 99;


const SHORT_PAYLOAD: usize = 10;


const INSIDE_RECORD: usize = 30;


const CUT_IN_PAYLOAD: usize = 40;


const CUT_IN_HEADER: usize = 10;


const OVERSIZE: usize = 5000;


const FIFTH: u64 = 5;


const NINTH: u64 = 9;


const ANSWER: u64 = 42;


const HALF: usize = 2;


#[cfg(unix)]
const ROTATED_FILES: usize = 2;


const MIN_SEGMENTS: u64 = 2;


const SMALL_LISTING: usize = 5;


const DOT_ENTRIES: usize = 2;


const MAX_FILL_APPENDS: u64 = 6000;


fn config() -> SpoolConfig {
    SpoolConfig {
        segment_max_bytes: SEGMENT,
        total_max_bytes: TOTAL,
    }
}


fn scratch() -> Result<TempDir, Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
    fs::create_dir_all(&root)?;
    Ok(tempfile::Builder::new().prefix("spool-").tempdir_in(root)?)
}


fn open_in(dir: &TempDir) -> Result<Spool, SpoolError> {
    open_spool(dir.path(), config())
}


fn push(spool: &mut Spool, priority: Priority, count: u64) -> TestResult {
    (0..count).try_for_each(|_| append(spool, priority, &[b'x'; PAYLOAD]).map(drop))?;
    Ok(())
}


fn sequences(spool: &Spool, from: u64) -> Result<Vec<u64>, SpoolError> {
    Ok(read_from(spool, from, ALL)?.iter().map(|record| record.sequence).collect())
}


fn segment_files(dir: &TempDir) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = fs::read_dir(dir.path())?
        .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|name| name.ends_with(".seg"))
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}


fn last_segment(dir: &TempDir) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let names = segment_files(dir)?;
    Ok(dir.path().join(names.last().ok_or("no segment")?))
}


fn append_raw(path: &Path, bytes: &[u8]) -> TestResult {
    OpenOptions::new().append(true).open(path)?.write_all(bytes)?;
    Ok(())
}


fn flip(bytes: &mut [u8], index: usize) -> TestResult {
    bytes.get_mut(index).map(|byte| *byte ^= 1).ok_or("short segment")?;
    Ok(())
}


fn low_record(sequence: u64, payload_len: usize) -> Record {
    Record {
        priority: Priority::Low,
        sequence,
        payload: vec![1; payload_len],
    }
}


#[test]
fn replay_is_in_order_across_segments() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, REPLAYED)?;
    assert_eq!(sequences(&spool, 0)?, (0..REPLAYED).collect::<Vec<_>>());
    assert_eq!(sequences(&spool, SOME)?, (SOME..REPLAYED).collect::<Vec<_>>());
    assert_eq!(read_from(&spool, 0, LIMIT)?.len(), LIMIT);
    assert_eq!(spool_stats(&spool).segments, LIMIT);
    assert_eq!(read_from(&spool, REPLAYED, ALL)?, Vec::<Record>::new());
    Ok(())
}


#[test]
fn both_caps_hold_and_the_oldest_low_priority_goes_first() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::High, SEGMENT_FRAMES)?;
    push(&mut spool, Priority::Low, DOUBLE_SEGMENT_FRAMES)?;
    assert!(!spool_stats(&spool).saturated);
    push(&mut spool, Priority::Low, 1)?;
    let stats = spool_stats(&spool);
    assert!(stats.saturated);
    assert_eq!((stats.dropped_low, stats.dropped_high), (SEGMENT_FRAMES, 0));
    assert!(stats.total_bytes <= TOTAL);
    let expected: Vec<u64> = (0..SEGMENT_FRAMES).chain(DOUBLE_SEGMENT_FRAMES..OVER_TOTAL_FRAMES).collect();
    assert_eq!(sequences(&spool, 0)?, expected);
    Ok(())
}


#[test]
fn mixed_segments_count_as_high_and_the_oldest_of_any_goes_last() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, FEW)?;
    push(&mut spool, Priority::High, 1)?;
    push(&mut spool, Priority::High, DOUBLE_SEGMENT_FRAMES)?;
    push(&mut spool, Priority::High, 1)?;
    let stats = spool_stats(&spool);
    assert_eq!((stats.dropped_low, stats.dropped_high), (FEW, 1));
    assert!(stats.saturated);
    assert!(stats.total_bytes <= TOTAL);
    assert_eq!(sequences(&spool, 0)?, (SEGMENT_FRAMES..OVER_TOTAL_FRAMES).collect::<Vec<_>>());
    Ok(())
}


#[test]
fn a_long_flood_never_exceeds_the_total_cap() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::High, FLOOD)?;
    let stats = spool_stats(&spool);
    assert!(stats.total_bytes <= TOTAL);
    assert_eq!(stats.dropped_high + (stats.total_bytes / FRAME), FLOOD);
    assert_eq!(stats.next_sequence, FLOOD);
    Ok(())
}


#[test]
fn acknowledge_deletes_segments_and_clears_saturation() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, OVER_TOTAL_FRAMES)?;
    assert!(spool_stats(&spool).saturated);
    acknowledge(&mut spool, HALF_ACK)?;
    assert_eq!(sequences(&spool, 0)?, (DOUBLE_SEGMENT_FRAMES..OVER_TOTAL_FRAMES).collect::<Vec<_>>());
    assert!(!spool_stats(&spool).saturated);
    assert_eq!(segment_files(&dir)?.len(), MIN_SEGMENTS as usize);
    acknowledge(&mut spool, TOTAL_FRAMES)?;
    let stats = spool_stats(&spool);
    assert_eq!((stats.segments, stats.total_bytes, stats.next_sequence), (1, 0, OVER_TOTAL_FRAMES));
    assert_eq!(segment_files(&dir)?.len(), 1);
    Ok(())
}


#[test]
fn a_partial_acknowledgement_keeps_the_segment() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, REPLAYED)?;
    acknowledge(&mut spool, PARTIAL_ACK)?;
    assert_eq!(sequences(&spool, 0)?, (0..REPLAYED).collect::<Vec<_>>());
    assert!(!spool_stats(&spool).saturated);
    assert_eq!(segment_files(&dir)?.len(), LIMIT);
    Ok(())
}


#[test]
fn a_stalled_reader_never_blocks_append() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, STALLED)?;
    assert_eq!(spool_stats(&spool).next_sequence, STALLED);
    Ok(())
}


#[test]
fn reopen_keeps_the_sequence() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, SOME)?;
    push(&mut spool, Priority::High, 1)?;
    drop(spool);
    let mut reopened = open_in(&dir)?;
    assert_eq!(spool_stats(&reopened).next_sequence, SOME + 1);
    assert_eq!(append(&mut reopened, Priority::High, b"next")?, SOME + 1);
    assert_eq!(sequences(&reopened, 0)?, (0..=SOME + 1).collect::<Vec<_>>());
    Ok(())
}


#[test]
fn reopen_after_a_full_acknowledgement_keeps_the_sequence() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, FEW)?;
    acknowledge(&mut spool, FEW - 1)?;
    drop(spool);
    let reopened = open_in(&dir)?;
    assert_eq!(spool_stats(&reopened).next_sequence, FEW);
    Ok(())
}


#[test]
fn reopen_enforces_a_smaller_cap() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_spool(
        dir.path(),
        SpoolConfig {
            segment_max_bytes: SEGMENT,
            total_max_bytes: TOTAL * BIG_TOTAL_FACTOR,
        },
    )?;
    push(&mut spool, Priority::Low, BIG_FILL)?;
    drop(spool);
    let reopened = open_in(&dir)?;
    let stats = spool_stats(&reopened);
    assert!(stats.total_bytes <= TOTAL);
    assert!(stats.dropped_low > 0);
    Ok(())
}


#[test]
fn a_torn_tail_is_truncated_and_counted() -> TestResult {
    let cut: Vec<u8> = encode_frame(&low_record(FEW, PAYLOAD))?.into_iter().take(CUT_PAYLOAD_BYTES).collect();
    let lying_length = [
        u32::MAX.to_le_bytes().to_vec(),
        vec![0; FRAME_HEADER_BYTES - LEN_FIELD_BYTES + ZERO_BODY_BYTES],
    ]
    .concat();
    let tails: Vec<Vec<u8>> = vec![
        b"abc".to_vec(),
        cut,
        lying_length,
        encode_frame(&low_record(WRONG_SEQUENCE, SHORT_PAYLOAD))?,
    ];
    tails.iter().try_for_each(|tail| -> TestResult {
        let dir = scratch()?;
        let mut spool = open_in(&dir)?;
        push(&mut spool, Priority::Low, FEW)?;
        drop(spool);
        append_raw(&last_segment(&dir)?, tail)?;
        let reopened = open_in(&dir)?;
        let stats = spool_stats(&reopened);
        assert_eq!((stats.truncated_tails, stats.next_sequence, stats.total_bytes), (1, FEW, FEW * FRAME));
        assert_eq!(fs::metadata(last_segment(&dir)?)?.len(), FEW * FRAME);
        assert_eq!(sequences(&reopened, 0)?, (0..FEW).collect::<Vec<_>>());
        Ok(())
    })
}


#[test]
fn a_flipped_byte_truncates_from_the_bad_record() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, FEW)?;
    drop(spool);
    let path = last_segment(&dir)?;
    let mut bytes = fs::read(&path)?;
    flip(&mut bytes, usize::try_from(FRAME)? + INSIDE_RECORD)?;
    fs::write(&path, bytes)?;
    let reopened = open_in(&dir)?;
    assert_eq!(sequences(&reopened, 0)?, vec![0]);
    assert_eq!(spool_stats(&reopened).truncated_tails, 1);
    Ok(())
}


#[test]
fn a_segment_changed_after_open_is_reported() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, FEW)?;
    let path = last_segment(&dir)?;
    let original = fs::read(&path)?;
    let mut first_bad = original.clone();
    flip(&mut first_bad, INSIDE_RECORD)?;
    fs::write(&path, &first_bad)?;
    assert!(matches!(read_from(&spool, 0, ALL), Err(SpoolError::Corrupt(0))));
    fs::write(&path, original.get(..CUT_IN_PAYLOAD).ok_or("short")?)?;
    assert!(matches!(read_from(&spool, 0, ALL), Err(SpoolError::Corrupt(0))));
    fs::write(&path, original.get(..CUT_IN_HEADER).ok_or("short")?)?;
    assert!(matches!(read_from(&spool, 0, ALL), Err(SpoolError::Io(_))));
    let mut second_bad = original;
    flip(&mut second_bad, usize::try_from(FRAME)? + INSIDE_RECORD)?;
    fs::write(&path, second_bad)?;
    assert!(matches!(read_from(&spool, 1, ALL), Err(SpoolError::Corrupt(1))));
    Ok(())
}


#[test]
fn empty_non_last_segments_and_foreign_entries_are_handled() -> TestResult {
    let dir = scratch()?;
    fs::write(segment_path(dir.path(), 0), b"")?;
    fs::write(segment_path(dir.path(), FIFTH), b"")?;
    fs::write(dir.path().join("notes.txt"), b"x")?;
    fs::create_dir(segment_path(dir.path(), NINTH))?;
    let spool = open_in(&dir)?;
    assert_eq!(spool_stats(&spool).next_sequence, FIFTH);
    assert!(!segment_path(dir.path(), 0).exists());
    Ok(())
}


#[test]
fn too_many_segment_files_are_refused() -> TestResult {
    let dir = scratch()?;
    (0..=u64::try_from(MAX_SEGMENT_FILES)?).try_for_each(|first| fs::write(segment_path(dir.path(), first), b""))?;
    assert!(matches!(open_in(&dir), Err(SpoolError::TooManySegments)));
    Ok(())
}


#[test]
fn an_oversized_payload_is_refused() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    assert!(matches!(
        append(&mut spool, Priority::Low, &[0; OVERSIZE]),
        Err(SpoolError::PayloadTooLarge)
    ));
    assert_eq!(spool_stats(&spool).next_sequence, 0);
    Ok(())
}


#[test]
fn a_colliding_segment_file_fails_the_rotation() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, SEGMENT_FRAMES)?;
    fs::write(segment_path(dir.path(), SEGMENT_FRAMES), b"")?;
    assert!(matches!(append(&mut spool, Priority::Low, &[0; PAYLOAD]), Err(SpoolError::Io(_))));
    Ok(())
}


#[test]
fn a_missing_segment_fails_the_scan() -> TestResult {
    let dir = scratch()?;
    assert!(matches!(scan_segment(&open_directory(dir.path())?, 0), Err(SpoolError::Io(_))));
    Ok(())
}


#[test]
fn a_vanished_segment_is_forgotten_by_the_acknowledgement() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, SOME)?;
    fs::remove_file(segment_path(dir.path(), 0))?;
    acknowledge(&mut spool, FIFTH)?;
    assert!(spool_stats(&spool).total_bytes < FRAME * SEGMENT_FRAMES);
    Ok(())
}


#[test]
fn an_unremovable_segment_stays_tracked_in_the_acknowledgement() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, SOME)?;
    fs::remove_file(segment_path(dir.path(), 0))?;
    fs::create_dir(segment_path(dir.path(), 0))?;
    assert!(matches!(acknowledge(&mut spool, FIFTH), Err(SpoolError::Io(_))));
    Ok(())
}


#[test]
fn a_vanished_segment_is_forgotten_by_the_drop() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, TOTAL_FRAMES)?;
    fs::remove_file(segment_path(dir.path(), 0))?;
    push(&mut spool, Priority::Low, 1)?;
    assert!(spool_stats(&spool).saturated);
    assert!(spool_stats(&spool).total_bytes <= TOTAL);
    Ok(())
}


#[test]
fn an_unremovable_segment_fails_the_drop() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, TOTAL_FRAMES)?;
    fs::remove_file(segment_path(dir.path(), 0))?;
    fs::create_dir(segment_path(dir.path(), 0))?;
    assert!(matches!(append(&mut spool, Priority::Low, &[0; PAYLOAD]), Err(SpoolError::Io(_))));
    Ok(())
}


#[test]
fn the_directory_listing_is_bounded() -> TestResult {
    let dir = scratch()?;
    (0..SMALL_LISTING).try_for_each(|index| fs::write(dir.path().join(format!("f{index}")), b""))?;
    let handle = open_directory(dir.path())?;
    assert!(matches!(regular_file_names(&handle, SMALL_LISTING), Err(SpoolError::TooManyEntries)));
    assert_eq!(regular_file_names(&handle, SMALL_LISTING + DOT_ENTRIES)?.len(), SMALL_LISTING);
    Ok(())
}


#[test]
fn a_spool_filled_at_the_maximum_ratio_reopens() -> TestResult {
    let dir = scratch()?;
    let at_ratio = SpoolConfig {
        segment_max_bytes: SEGMENT,
        total_max_bytes: SEGMENT * MAX_SEGMENTS_IN_TOTAL,
    };
    let mut spool = open_spool(dir.path(), at_ratio.clone())?;
    (0..MAX_FILL_APPENDS).try_for_each(|index| {
        let payload_len = if index % MIN_SEGMENTS == 0 { 0 } else { MAX_PAYLOAD_BYTES };
        append(&mut spool, Priority::Low, &vec![b'x'; payload_len]).map(drop)
    })?;
    let filled = spool_stats(&spool);
    assert!(filled.segments > MAX_SEGMENT_FILES / HALF / HALF);
    assert!(filled.segments <= MAX_SEGMENTS_IN_TOTAL as usize);
    drop(spool);
    let reopened = open_spool(dir.path(), at_ratio)?;
    assert_eq!(spool_stats(&reopened).next_sequence, MAX_FILL_APPENDS);
    Ok(())
}


#[test]
fn an_unremovable_victim_fails_the_rotation_at_the_count_cap() -> TestResult {
    let dir = scratch()?;
    let at_ratio = SpoolConfig {
        segment_max_bytes: SEGMENT,
        total_max_bytes: SEGMENT * MAX_SEGMENTS_IN_TOTAL,
    };
    let mut spool = open_spool(dir.path(), at_ratio)?;
    let full = vec![b'x'; MAX_PAYLOAD_BYTES];
    (0..MAX_SEGMENTS_IN_TOTAL).try_for_each(|_| append(&mut spool, Priority::Low, &full).map(drop))?;
    assert_eq!(spool_stats(&spool).segments, MAX_SEGMENTS_IN_TOTAL as usize);
    fs::remove_file(segment_path(dir.path(), 0))?;
    fs::create_dir(segment_path(dir.path(), 0))?;
    assert!(matches!(append(&mut spool, Priority::Low, &full), Err(SpoolError::Io(_))));
    Ok(())
}


#[test]
fn opening_more_segments_than_the_count_cap_drops_the_oldest() -> TestResult {
    let dir = scratch()?;
    let over = MAX_SEGMENTS_IN_TOTAL + EXTRA_SEGMENTS;
    (0..over).try_for_each(|first| -> TestResult {
        let record = Record {
            priority: Priority::Low,
            sequence: first,
            payload: Vec::new(),
        };
        fs::write(segment_path(dir.path(), first), encode_frame(&record)?)?;
        Ok(())
    })?;
    let at_ratio = SpoolConfig {
        segment_max_bytes: SEGMENT,
        total_max_bytes: SEGMENT * MAX_SEGMENTS_IN_TOTAL,
    };
    let spool = open_spool(dir.path(), at_ratio)?;
    assert_eq!(spool_stats(&spool).segments, MAX_SEGMENTS_IN_TOTAL as usize);
    assert_eq!(spool_stats(&spool).dropped_low, EXTRA_SEGMENTS);
    Ok(())
}


#[test]
fn mixed_priorities_never_exceed_the_segment_count_cap() -> TestResult {
    let dir = scratch()?;
    let at_ratio = SpoolConfig {
        segment_max_bytes: SEGMENT,
        total_max_bytes: SEGMENT * MAX_SEGMENTS_IN_TOTAL,
    };
    let mut spool = open_spool(dir.path(), at_ratio.clone())?;
    let large = vec![b'x'; MAX_PAYLOAD_BYTES - 1];
    (0..MIXED_CYCLES).try_for_each(|_| {
        append(&mut spool, Priority::High, b"")?;
        append(&mut spool, Priority::Low, &large).map(drop)
    })?;
    assert!(spool_stats(&spool).segments <= MAX_SEGMENTS_IN_TOTAL as usize);
    drop(spool);
    let reopened = open_spool(dir.path(), at_ratio)?;
    assert!(spool_stats(&reopened).segments <= MAX_SEGMENTS_IN_TOTAL as usize);
    assert_eq!(spool_stats(&reopened).next_sequence, MIXED_CYCLES * APPENDS_PER_CYCLE);
    Ok(())
}


#[cfg(unix)]
#[test]
fn the_directory_is_checked_at_open() -> TestResult {
    let dir = scratch()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(matches!(open_in(&dir), Err(SpoolError::WritableByOthers)));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE))?;
    assert!(open_in(&dir).is_ok());
    let file = dir.path().join("plain");
    fs::write(&file, b"")?;
    assert!(matches!(open_spool(&file, config()), Err(SpoolError::NotDirectory)));
    assert!(matches!(open_spool(&dir.path().join("absent"), config()), Err(SpoolError::Io(_))));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlinked_directory_is_refused() -> TestResult {
    let dir = scratch()?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    assert!(matches!(open_spool(&link, config()), Err(SpoolError::NotDirectory)));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_directory_replaced_after_open_is_not_followed() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    let moved = dir.path().with_extension("moved");
    fs::rename(dir.path(), &moved)?;
    fs::create_dir(dir.path())?;
    push(&mut spool, Priority::Low, SOME)?;
    assert!(segment_files(&dir)?.is_empty());
    assert_eq!(fs::read_dir(&moved)?.count(), ROTATED_FILES + 1);
    fs::remove_dir_all(&moved)?;
    Ok(())
}


#[test]
fn a_foreign_owner_is_refused() -> TestResult {
    let own = directory_facts(&open_directory(scratch()?.path())?)?;
    assert!(own.is_directory);
    assert!(check_directory(&own).is_ok());
    let foreign = DirectoryFacts {
        owner: own.expected_owner + 1,
        ..own
    };
    assert!(matches!(check_directory(&foreign), Err(SpoolError::WrongOwner)));
    let not_directory = DirectoryFacts { is_directory: false, ..own };
    assert!(matches!(check_directory(&not_directory), Err(SpoolError::NotDirectory)));
    Ok(())
}


#[test]
fn sizes_are_validated() -> TestResult {
    assert!(check_config(&config()).is_ok());
    let sizes = [
        (SEGMENT - 1, TOTAL),
        (MAX_SEGMENT_BYTES + 1, u64::MAX),
        (SEGMENT, SEGMENT * MIN_SEGMENTS - 1),
        (SEGMENT, SEGMENT * MAX_SEGMENTS_IN_TOTAL + 1),
    ];
    sizes.iter().try_for_each(|(segment_max_bytes, total_max_bytes)| -> TestResult {
        let bad = SpoolConfig {
            segment_max_bytes: *segment_max_bytes,
            total_max_bytes: *total_max_bytes,
        };
        assert!(matches!(check_config(&bad), Err(SpoolError::BadSizes)));
        Ok(())
    })
}


#[test]
fn segment_names_are_strict() -> TestResult {
    assert_eq!(parse_segment_name("00000000000000000042.seg"), Some(ANSWER));
    assert_eq!(parse_segment_name("42.seg"), None);
    assert_eq!(parse_segment_name("0000000000000000004x.seg"), None);
    assert_eq!(parse_segment_name("00000000000000000042.tmp"), None);
    assert_eq!(parse_segment_name("99999999999999999999.seg"), None);
    Ok(())
}


#[test]
fn acknowledging_an_empty_spool_changes_nothing() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    acknowledge(&mut spool, 0)?;
    assert_eq!(spool_stats(&spool).segments, 1);
    assert_eq!(segment_files(&dir)?.len(), 1);
    Ok(())
}


fn write_half_then_fail(file: &mut File, frame: &[u8]) -> io::Result<()> {
    file.write_all(frame.get(..frame.len() / HALF).ok_or(io::ErrorKind::InvalidInput)?)?;
    Err(io::ErrorKind::StorageFull.into())
}


#[test]
fn a_partial_write_is_cut_back_and_confirmed_records_survive() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    push(&mut spool, Priority::Low, FEW)?;
    assert!(append_with(&mut spool, Priority::Low, &[b'y'; PAYLOAD], write_half_then_fail).is_err());
    assert_eq!(spool_stats(&spool).next_sequence, FEW);
    push(&mut spool, Priority::High, 1)?;
    assert_eq!(sequences(&spool, 0)?, (0..=FEW).collect::<Vec<_>>());
    drop(spool);
    let reopened = open_in(&dir)?;
    assert_eq!(spool_stats(&reopened).truncated_tails, 0);
    assert_eq!(sequences(&reopened, 0)?, (0..=FEW).collect::<Vec<_>>());
    Ok(())
}


fn write_one_byte_then_fail(file: &mut File, frame: &[u8]) -> io::Result<()> {
    file.write_all(frame.get(..1).ok_or(io::ErrorKind::InvalidInput)?)?;
    Err(io::ErrorKind::StorageFull.into())
}


#[test]
fn a_failed_write_on_a_fresh_segment_leaves_it_empty() -> TestResult {
    let dir = scratch()?;
    let mut spool = open_in(&dir)?;
    assert!(append_with(&mut spool, Priority::Low, &[b'y'; PAYLOAD], write_one_byte_then_fail).is_err());
    assert_eq!(fs::metadata(last_segment(&dir)?)?.len(), 0);
    assert_eq!(append(&mut spool, Priority::Low, b"ok")?, 0);
    Ok(())
}
