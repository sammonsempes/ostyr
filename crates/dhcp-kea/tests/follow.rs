#[path = "common/types.rs"]
mod types;


use core_export::ecs::EcsEvent;
use dhcp_kea::error::{HeaderError, KeaError};
use dhcp_kea::follow::{malformed_summary, poll, remember, Counts, FollowState, Limits, MAX_OPEN_HANDLES};
use std::fs::{create_dir, metadata, remove_file, rename, write, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use types::TestResult;


const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const ROW_1: &str = "10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,";


const ROW_2: &str = "10.0.0.2,aa:bb:cc:dd:ee:02,01,3600,1700003600,1,0,0,host2.example.,0,";


const ROW_3: &str = "10.0.0.3,aa:bb:cc:dd:ee:03,01,3600,1700003600,1,0,0,host3.example.,0,";


const ROW_4: &str = "10.0.0.4,aa:bb:cc:dd:ee:04,01,3600,1700003600,1,0,0,host4.example.,0,";


const ROW_1_RENEWED: &str = "10.0.0.1,aa:bb:cc:dd:ee:01,01,3600,1700007200,1,0,0,host1.example.,0,";


const BAD_ADDRESS: &str = "not-an-address,aa:bb:cc:dd:ee:01,01,3600,1700003600,1,0,0,host1.example.,0,";


const ROW_5: &str = "10.0.0.5,aa:bb:cc:dd:ee:05,01,3600,1700003600,1,0,0,host5.example.,0,";


const ROW_6: &str = "10.0.0.6,aa:bb:cc:dd:ee:06,01,3600,1700003600,1,0,0,host6.example.,0,";


const PENDING_ROWS: usize = 40;


const ROTATIONS: usize = 12;


const MAX_DRAIN_POLLS: usize = 8;


const SIX: u64 = 6;


const THREE: u64 = 3;


const THREE_LINES: usize = 3;


const FIVE: u64 = 5;


const TWO: u64 = 2;


const HALF: usize = 2;


const TWO_EVENTS: usize = 2;


const FOUR_EVENTS: usize = 4;


const NEWEST_EXPIRE: i64 = 4_000_000_000_000;


const SMALL_SEEN: usize = 2;


const SMALL_LINES: usize = 2;


const HUGE_LINE: usize = 100_000;


const MANY_COLUMNS: usize = 1_000;


const HUGE_HEADER_COLUMNS: usize = 100_000;


struct Run {
    state: FollowState,
    counts: Counts,
}


fn fresh() -> Run {
    Run {
        state: FollowState::default(),
        counts: Counts::default(),
    }
}


fn step(path: &Path, run: &mut Run, limits: &Limits) -> Result<Vec<String>, KeaError> {
    let mut events: Vec<EcsEvent> = Vec::new();
    poll(path, &mut run.state, limits, &mut run.counts, &mut events)?;
    Ok(events
        .iter()
        .filter_map(|event| event.source.as_ref().and_then(|source| source.ip.clone()))
        .collect())
}


fn lines(rows: &[&str]) -> String {
    rows.iter().map(|row| format!("{row}\n")).collect()
}


fn append(path: &Path, text: &str) -> TestResult {
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(text.as_bytes())?;
    Ok(())
}


#[test]
fn rows_are_read_once_as_the_file_grows() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_2]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1", "10.0.0.2"]);
    assert_eq!(run.state.offset, metadata(&path)?.len());
    assert!(step(&path, &mut run, &Limits::default())?.is_empty());
    append(&path, &lines(&[ROW_3]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.3"]);
    assert_eq!((run.counts.processed, run.counts.restarts, run.counts.duplicate), (THREE, 0, 0));
    Ok(())
}


#[test]
fn a_half_written_row_waits_for_its_newline() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), 1);
    let before = run.state.offset;
    let (first, second) = ROW_2.split_at(ROW_2.len() / HALF);
    append(&path, first)?;
    assert!(step(&path, &mut run, &Limits::default())?.is_empty());
    assert_eq!(run.state.offset, before);
    append(&path, &format!("{second}\n"))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2"]);
    Ok(())
}


#[test]
fn a_new_inode_after_cleanup_loses_and_repeats_nothing() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_1_RENEWED, ROW_2, ROW_3]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), FOUR_EVENTS);
    let compacted = directory.path().join("kea-leases4.csv.completed");
    write(&compacted, lines(&[HEADER, ROW_1_RENEWED, ROW_2, ROW_3, ROW_4]))?;
    assert!(metadata(&compacted)?.len() < metadata(&path)?.len() + lines(&[ROW_4]).len() as u64);
    rename(&compacted, &path)?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.4"]);
    assert_eq!((run.counts.restarts, run.counts.duplicate, run.counts.processed), (1, THREE, FIVE));
    append(&path, &lines(&[ROW_1]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), 0);
    Ok(())
}


#[test]
fn a_row_appended_before_a_kea_rotation_is_read_from_the_old_handle() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    append(&path, &lines(&[ROW_2]))?;
    rename(&path, directory.path().join("kea-leases4.csv.1"))?;
    write(&path, lines(&[HEADER]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2"]);
    append(&path, &lines(&[ROW_3]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.3"]);
    assert_eq!((run.counts.restarts, run.counts.duplicate, run.counts.processed), (1, 0, THREE));
    Ok(())
}


#[test]
fn a_long_unread_tail_is_drained_over_several_polls_before_the_switch() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    append(&path, &lines(&[ROW_2, ROW_3, ROW_4]))?;
    rename(&path, directory.path().join("kea-leases4.csv.1"))?;
    write(&path, lines(&[HEADER, ROW_1_RENEWED]))?;
    let limits = Limits {
        max_lines: SMALL_LINES,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.2", "10.0.0.3"]);
    assert_eq!(run.counts.restarts, 0);
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.4", "10.0.0.1"]);
    assert_eq!(run.counts.restarts, 1);
    Ok(())
}


#[test]
fn a_file_shorter_than_the_offset_restarts_at_the_header() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_2]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), TWO_EVENTS);
    write(&path, lines(&[HEADER, ROW_3]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.3"]);
    assert_eq!(run.counts.restarts, 1);
    Ok(())
}


#[test]
fn the_seen_set_is_bounded_and_evictions_are_counted() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_2, ROW_3, ROW_4]))?;
    let mut run = fresh();
    let limits = Limits {
        max_seen: SMALL_SEEN,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?.len(), FOUR_EVENTS);
    assert_eq!(run.counts.evicted, TWO);
    assert_eq!(run.state.seen.len(), SMALL_SEEN);
    let mut counts = Counts::default();
    assert!(remember(
        &mut run.state.seen,
        (NEWEST_EXPIRE, "a".to_string(), "b".to_string()),
        SMALL_SEEN,
        &mut counts
    ));
    assert!(!remember(
        &mut run.state.seen,
        (NEWEST_EXPIRE, "a".to_string(), "b".to_string()),
        SMALL_SEEN,
        &mut counts
    ));
    Ok(())
}


#[test]
fn a_poll_reads_at_most_its_line_budget_and_resumes() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_2, ROW_3]))?;
    let mut run = fresh();
    let limits = Limits {
        max_lines: SMALL_LINES,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.1"]);
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.2", "10.0.0.3"]);
    assert!(step(&path, &mut run, &limits)?.is_empty());
    Ok(())
}


#[test]
fn a_missing_file_is_counted_and_read_when_it_appears() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    let mut run = fresh();
    assert!(step(&path, &mut run, &Limits::default())?.is_empty());
    assert_eq!(run.counts.absent, 1);
    write(&path, lines(&[HEADER, ROW_1]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), 1);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_is_refused_even_when_it_points_at_a_regular_file() -> TestResult {
    let directory = tempdir()?;
    let target = directory.path().join("target.csv");
    let link = directory.path().join("leases.csv");
    write(&target, lines(&[HEADER, ROW_1]))?;
    std::os::unix::fs::symlink(&target, &link)?;
    assert!(matches!(step(&link, &mut fresh(), &Limits::default()), Err(KeaError::NotRegular)));
    Ok(())
}


#[test]
fn a_directory_is_refused() -> TestResult {
    let directory = tempdir()?;
    let inner = directory.path().join("leases.csv");
    create_dir(&inner)?;
    assert!(matches!(step(&inner, &mut fresh(), &Limits::default()), Err(KeaError::NotRegular)));
    Ok(())
}


fn make_fifo(path: &Path) -> TestResult {
    let status = Command::new("mkfifo").arg(path).status()?;
    assert!(status.success());
    Ok(())
}


#[test]
fn a_fifo_without_a_writer_is_refused_and_never_blocks() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    make_fifo(&path)?;
    assert!(matches!(step(&path, &mut fresh(), &Limits::default()), Err(KeaError::NotRegular)));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_to_a_fifo_is_refused_and_never_blocks() -> TestResult {
    let directory = tempdir()?;
    let fifo = directory.path().join("pipe");
    let link = directory.path().join("leases.csv");
    make_fifo(&fifo)?;
    std::os::unix::fs::symlink(&fifo, &link)?;
    assert!(matches!(step(&link, &mut fresh(), &Limits::default()), Err(KeaError::NotRegular)));
    Ok(())
}


#[test]
fn a_file_swapped_for_a_fifo_and_back_is_read_again_by_the_same_reader() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), 1);
    let kept = directory.path().join("kept.csv");
    rename(&path, &kept)?;
    assert!(step(&path, &mut run, &Limits::default())?.is_empty());
    make_fifo(&path)?;
    assert!(matches!(step(&path, &mut run, &Limits::default()), Err(KeaError::NotRegular)));
    remove_file(&path)?;
    write(&path, lines(&[HEADER, ROW_2]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2"]);
    assert_eq!((run.counts.absent, run.counts.restarts), (1, 1));
    Ok(())
}


#[test]
fn a_path_the_system_rejects_is_an_io_error() -> TestResult {
    let result = step(Path::new("bad\0path"), &mut fresh(), &Limits::default());
    assert!(matches!(result, Err(KeaError::Io(_))));
    Ok(())
}


#[test]
fn a_file_that_is_not_a_lease_file_is_refused_at_the_header() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")?;
    let mut run = fresh();
    assert!(matches!(
        step(&path, &mut run, &Limits::default()),
        Err(KeaError::Header(HeaderError::Missing("hwaddr")))
    ));
    assert_eq!(run.state.offset, 0);
    Ok(())
}


#[test]
fn a_header_that_repeats_address_is_refused() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[&format!("{HEADER},address"), ROW_1]))?;
    assert!(matches!(
        step(&path, &mut fresh(), &Limits::default()),
        Err(KeaError::Header(HeaderError::Duplicate("address")))
    ));
    Ok(())
}


#[test]
fn a_header_with_too_many_columns_is_refused_whatever_its_size() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[&vec!["x"; MANY_COLUMNS].join(",")]))?;
    assert!(matches!(
        step(&path, &mut fresh(), &Limits::default()),
        Err(KeaError::Header(HeaderError::TooManyColumns { .. }))
    ));
    write(&path, lines(&[&vec!["x"; HUGE_HEADER_COLUMNS].join(",")]))?;
    assert!(matches!(
        step(&path, &mut fresh(), &Limits::default()),
        Err(KeaError::Header(HeaderError::TooLong))
    ));
    write(&path, b"address,\xff\n")?;
    assert!(matches!(
        step(&path, &mut fresh(), &Limits::default()),
        Err(KeaError::Header(HeaderError::Utf8(_)))
    ));
    Ok(())
}


#[test]
fn an_oversized_row_is_counted_and_the_next_row_still_read() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    let huge = "a".repeat(HUGE_LINE);
    write(&path, lines(&[HEADER, &huge, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    append(&path, &huge)?;
    assert!(step(&path, &mut run, &Limits::default())?.is_empty());
    assert_eq!(run.counts.malformed.get("line-too-long"), Some(&TWO));
    Ok(())
}


#[test]
fn malformed_rows_are_counted_per_kind_without_their_content() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    let mut bytes = lines(&[HEADER, BAD_ADDRESS, BAD_ADDRESS, ROW_2]).into_bytes();
    bytes.extend_from_slice(b"10.0.0.9,\xff\n\n");
    write(&path, bytes)?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2"]);
    let summary = malformed_summary(&run.counts);
    assert_eq!(summary, "address=2,column-count=1,not-utf8=1");
    assert!(!summary.contains("not-an-address"));
    Ok(())
}


#[test]
fn a_repeated_row_is_a_duplicate_and_a_renewal_is_a_new_event() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("leases.csv");
    write(&path, lines(&[HEADER, ROW_1, ROW_1, ROW_1_RENEWED]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?.len(), TWO_EVENTS);
    assert_eq!(run.counts.duplicate, 1);
    Ok(())
}


fn rotate(directory: &Path, path: &Path, rows: &[&str]) -> TestResult {
    rename(path, directory.join("kea-leases4.csv.1"))?;
    write(path, lines(rows))?;
    Ok(())
}


fn collect(path: &Path, run: &mut Run, limits: &Limits) -> Result<Vec<String>, KeaError> {
    (0..MAX_DRAIN_POLLS).try_fold(Vec::new(), |mut all, _| {
        all.extend(step(path, run, limits)?);
        Ok(all)
    })
}


#[test]
fn a_rotation_during_a_long_drain_loses_no_file() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    append(&path, &lines(&[ROW_2, ROW_3, ROW_4]))?;
    rotate(directory.path(), &path, &[HEADER, ROW_5])?;
    let limits = Limits {
        max_lines: SMALL_LINES,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.2", "10.0.0.3"]);
    rotate(directory.path(), &path, &[HEADER, ROW_6])?;
    assert_eq!(collect(&path, &mut run, &limits)?, ["10.0.0.4", "10.0.0.5", "10.0.0.6"]);
    assert_eq!((run.counts.restarts, run.counts.duplicate, run.counts.processed), (TWO, 0, SIX));
    assert!(run.state.queued.is_empty());
    Ok(())
}


#[test]
fn two_rotations_before_one_poll_read_the_old_tail_and_the_newest_file() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    append(&path, &lines(&[ROW_2]))?;
    rotate(directory.path(), &path, &[HEADER, ROW_3])?;
    let rotated = directory.path().join("kea-leases4.csv.1");
    rename(&rotated, directory.path().join("kea-leases4.csv.3"))?;
    rotate(directory.path(), &path, &[HEADER, ROW_4])?;
    set_compacted(directory.path(), &lines(&[HEADER, ROW_2, ROW_3]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2", "10.0.0.4", "10.0.0.3"]);
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (1, 0));
    Ok(())
}


const OLD_ROW: &str = "10.0.0.9,aa:bb:cc:dd:ee:09,01,3600,1600000000,1,0,0,host9.example.,0,";


const BAD_COMPACTED_ROW: &str = "not-an-address,aa:bb:cc:dd:ee:07,01,3600,1700003600,1,0,0,host7.example.,0,";


fn set_compacted(directory: &Path, text: &str) -> TestResult {
    let staging = directory.join("kea-leases4.csv.output");
    write(&staging, text)?;
    rename(&staging, directory.join("kea-leases4.csv.2"))?;
    Ok(())
}


fn started(directory: &Path) -> Result<(std::path::PathBuf, Run), Box<dyn std::error::Error>> {
    let path = directory.join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    Ok((path, run))
}


#[test]
fn the_compacted_file_at_start_is_remembered_and_never_replayed() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    set_compacted(directory.path(), &lines(&[HEADER, ROW_5]))?;
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.1"]);
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    set_compacted(directory.path(), &lines(&[HEADER, ROW_5, ROW_6, OLD_ROW]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.6"]);
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (1, 0));
    let mut restarted = fresh();
    assert_eq!(step(&path, &mut restarted, &Limits::default())?, ["10.0.0.1"]);
    assert_eq!(restarted.counts.recovered, 0);
    Ok(())
}


#[test]
fn a_row_older_than_the_oldest_seen_row_is_not_replayed() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    rotate(directory.path(), &path, &[HEADER, ROW_2])?;
    set_compacted(directory.path(), &lines(&[HEADER, OLD_ROW, ROW_1, ROW_3]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2", "10.0.0.3"]);
    assert_eq!(run.counts.recovered, 1);
    Ok(())
}


#[test]
fn a_rotation_without_a_readable_compacted_file_is_counted() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    assert_eq!(run.counts.unrecovered, 0);
    rotate(directory.path(), &path, &[HEADER, ROW_2])?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.2"]);
    assert_eq!(run.counts.unrecovered, 1);
    create_dir(directory.path().join("kea-leases4.csv.2"))?;
    rotate(directory.path(), &path, &[HEADER, ROW_3])?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.3"]);
    assert_eq!(run.counts.unrecovered, 1);
    std::fs::remove_dir(directory.path().join("kea-leases4.csv.2"))?;
    set_compacted(directory.path(), &lines(&[HEADER, ROW_6]))?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.6"]);
    remove_file(directory.path().join("kea-leases4.csv.2"))?;
    rotate(directory.path(), &path, &[HEADER, ROW_5])?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, ["10.0.0.5"]);
    assert_eq!(run.counts.unrecovered, TWO);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_compacted_path_that_is_not_a_regular_file_is_never_read_nor_blocking() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    let compacted = directory.path().join("kea-leases4.csv.2");
    make_fifo(&compacted)?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    remove_file(&compacted)?;
    let target = directory.path().join("target.csv");
    write(&target, lines(&[HEADER, ROW_6]))?;
    std::os::unix::fs::symlink(&target, &compacted)?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (0, 0));
    Ok(())
}


#[test]
fn an_unreadable_compacted_file_is_counted_once() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    set_compacted(directory.path(), "not,a,lease,file\n")?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    assert_eq!(run.counts.unrecovered, 1);
    set_compacted(directory.path(), "")?;
    assert_eq!(step(&path, &mut run, &Limits::default())?, Vec::<String>::new());
    assert_eq!(run.counts.unrecovered, 1);
    Ok(())
}


#[test]
fn a_long_compacted_file_is_read_over_several_polls_until_its_end() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    set_compacted(directory.path(), &lines(&[HEADER, BAD_COMPACTED_ROW, ROW_2, ROW_3, ROW_4]))?;
    let limits = Limits {
        max_lines: THREE_LINES,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.2"]);
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.3", "10.0.0.4"]);
    assert_eq!(step(&path, &mut run, &limits)?, Vec::<String>::new());
    assert_eq!(malformed_summary(&run.counts), "address=1");
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (THREE, 0));
    Ok(())
}


#[test]
fn a_compacted_file_replaced_before_its_end_counts_the_unread_part() -> TestResult {
    let directory = tempdir()?;
    let (path, mut run) = started(directory.path())?;
    set_compacted(directory.path(), &lines(&[HEADER, ROW_2, ROW_3, ROW_4, ROW_5]))?;
    let limits = Limits {
        max_lines: THREE_LINES,
        ..Limits::default()
    };
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.2", "10.0.0.3"]);
    set_compacted(directory.path(), &lines(&[HEADER, ROW_6]))?;
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.6"]);
    assert_eq!(run.counts.unrecovered, 1);
    Ok(())
}


#[test]
fn a_startup_pass_replaced_before_its_end_replays_nothing_and_loses_nothing() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    set_compacted(directory.path(), &lines(&[HEADER, ROW_2, ROW_3, ROW_4, ROW_5]))?;
    let limits = Limits {
        max_lines: THREE_LINES,
        ..Limits::default()
    };
    let mut run = fresh();
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.1"]);
    set_compacted(directory.path(), &lines(&[HEADER, ROW_2, ROW_3, ROW_4, ROW_5]))?;
    assert_eq!(step(&path, &mut run, &limits)?, Vec::<String>::new());
    assert_eq!(step(&path, &mut run, &limits)?, Vec::<String>::new());
    assert_eq!(step(&path, &mut run, &limits)?, Vec::<String>::new());
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (0, 0));
    set_compacted(directory.path(), &lines(&[HEADER, ROW_2, ROW_6]))?;
    assert_eq!(step(&path, &mut run, &limits)?, ["10.0.0.6"]);
    assert_eq!((run.counts.recovered, run.counts.unrecovered), (1, 0));
    Ok(())
}


#[test]
fn the_queue_of_open_handles_is_bounded_and_the_oldest_is_drained_first() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("kea-leases4.csv");
    write(&path, lines(&[HEADER, ROW_1]))?;
    let mut run = fresh();
    step(&path, &mut run, &Limits::default())?;
    let pending: Vec<String> = (0..PENDING_ROWS).map(|i| ROW_2.replace("10.0.0.2", &format!("10.9.0.{i}"))).collect();
    append(&path, &pending.iter().map(|row| format!("{row}\n")).collect::<String>())?;
    let limits = Limits {
        max_lines: 1,
        ..Limits::default()
    };
    (0..ROTATIONS).try_for_each(|_| {
        rotate(directory.path(), &path, &[HEADER, ROW_3])?;
        step(&path, &mut run, &limits).map(drop)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(run.state.queued.len(), MAX_OPEN_HANDLES);
    Ok(())
}
