#![cfg(unix)]


#[path = "support/files.rs"]
mod files;
#[path = "support/table.rs"]
mod table;
#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::list::{judge_list, open_list, read_entry, scan, sorted_keys, verify_unchanged, verify_unchanged_with};
use breached_passwords::model::{NtHash, HASH_BYTES, HASH_HEX_LEN};
use data_encoding::HEXLOWER;
use files::write_file;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use table::{entries, render};
use types::TestResult;
use zeroize::Zeroizing;


const LINE_ENDINGS: [&str; 2] = ["\n", "\r\n"];


const LIST_LINES: usize = 10_000;


const ZERO: [u8; HASH_BYTES] = [0u8; HASH_BYTES];


const OVERLONG_LINE: usize = 1000;


const WORLD_WRITABLE: u32 = 0o666;


const GROUP_WRITABLE: u32 = 0o664;


const READABLE: u32 = 0o644;


const OWNER_ONLY: u32 = 0o600;


const OTHER_USER: u32 = 1000;


const SMALL_LIST: usize = 200;


const MAX_LINES: u64 = 1_000;


const MANY_TARGETS: usize = 1_000;


const CLOCK_TICK: Duration = Duration::from_millis(50);


const HALF: u64 = 2;


const MIDDLE: usize = 5_000;


fn nt(bytes: [u8; HASH_BYTES]) -> NtHash {
    NtHash(Zeroizing::new(bytes))
}


fn plus_one(hash: [u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    u128::from_be_bytes(hash).wrapping_add(1).to_be_bytes()
}


fn failing_inspect(_: &File) -> io::Result<Metadata> {
    Err(io::Error::other("injected"))
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


struct Recorder<'a> {
    data: &'a [u8],
    position: usize,
    calls: Vec<(usize, usize)>,
}


impl Read for Recorder<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.calls.push((self.position, buffer.len()));
        let rest = self.data.get(self.position..).ok_or_else(|| io::Error::other("position"))?;
        let count = rest.len().min(buffer.len());
        buffer.iter_mut().zip(rest.iter()).for_each(|(slot, byte)| *slot = *byte);
        self.position += count;
        Ok(count)
    }
}


fn calls_for(text: &str, targets: &[NtHash]) -> Result<Vec<(usize, usize)>, Box<dyn std::error::Error>> {
    let mut recorder = Recorder {
        data: text.as_bytes(),
        position: 0,
        calls: Vec::new(),
    };
    let keys = sorted_keys(targets);
    let scanned = scan(&mut recorder, text.len() as u64, u64::MAX, &keys)?;
    assert_eq!(scanned.found.len(), keys.len());
    Ok(recorder.calls)
}


#[test]
fn every_present_hash_is_found_in_one_pass() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let absent = [ZERO, plus_one(table.first().ok_or("empty")?.0), [u8::MAX; HASH_BYTES]];
    LINE_ENDINGS.iter().try_for_each(|eol| -> TestResult {
        let path = write_file(&dir, "list.txt", render(&table, eol).as_bytes())?;
        let targets: Vec<NtHash> = table.iter().map(|entry| nt(entry.0)).chain(absent.iter().map(|hash| nt(*hash))).collect();
        let list = open_list(&path, &targets)?;
        assert_eq!(list.verdicts.len(), targets.len());
        let (present, missing) = list.verdicts.split_at(table.len());
        assert!(present.iter().all(|verdict| verdict.compromised));
        assert!(missing.iter().all(|verdict| !verdict.compromised));
        Ok(())
    })
}


#[test]
fn verdicts_follow_the_input_order_with_duplicates() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let first = table.first().ok_or("empty")?.0;
    let last = table.last().ok_or("empty")?.0;
    let targets = [nt(last), nt(ZERO), nt(first), nt(last), nt(ZERO)];
    let flags: Vec<bool> = open_list(&path, &targets)?.verdicts.iter().map(|verdict| verdict.compromised).collect();
    assert_eq!(flags, [true, false, true, true, false]);
    assert!(open_list(&path, &[])?.verdicts.is_empty());
    Ok(())
}


#[test]
fn the_reads_are_the_same_whatever_the_targets() -> TestResult {
    let table = entries(LIST_LINES);
    let text = render(&table, "\n");
    let listed = nt(table.get(MIDDLE).ok_or("short")?.0);
    let many: Vec<NtHash> = table.iter().take(MANY_TARGETS).map(|entry| nt(entry.0)).collect();
    let baseline = calls_for(&text, &[])?;
    assert!(baseline.len() > 1);
    assert_eq!(baseline, calls_for(&text, &[listed])?);
    assert_eq!(baseline, calls_for(&text, &[nt(ZERO)])?);
    assert_eq!(baseline, calls_for(&text, &many)?);
    let ends = [nt(table.first().ok_or("empty")?.0), nt(table.last().ok_or("empty")?.0)];
    assert_eq!(baseline, calls_for(&text, &ends)?);
    Ok(())
}


#[test]
fn the_pass_reads_every_byte_and_ends_at_the_end_of_the_list() -> TestResult {
    let table = entries(LIST_LINES);
    let text = render(&table, "\n");
    let first = nt(table.first().ok_or("empty")?.0);
    let calls = calls_for(&text, &[first])?;
    let last_read = calls.last().ok_or("no read")?;
    assert!(last_read.0 + last_read.1 >= text.len());
    assert!(calls.iter().map(|call| call.0).is_sorted());
    Ok(())
}


#[test]
fn hostile_lists_are_refused_at_open() -> TestResult {
    let table = entries(LIST_LINES);
    let first = table.first().ok_or("empty")?;
    let hash_text = render(&[*first], "");
    let dir = tempfile::tempdir()?;
    let overlong = "A".repeat(OVERLONG_LINE);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("unterminated", hash_text.clone().into_bytes()),
        ("overlong", format!("{overlong}\n").into_bytes()),
        ("overlong_without_newline", overlong.into_bytes()),
        ("not_hex", format!("{}:5\n", "Z".repeat(HASH_HEX_LEN)).into_bytes()),
        ("separators", "\n".repeat(OVERLONG_LINE).into_bytes()),
        ("duplicate", format!("{hash_text}\n{hash_text}\n").into_bytes()),
    ];
    cases.iter().try_for_each(|(name, content)| -> TestResult {
        let path = write_file(&dir, name, content)?;
        assert!(open_list(&path, &[]).is_err(), "{name}");
        Ok(())
    })
}


#[test]
fn a_malformed_line_anywhere_fails_the_open_whatever_the_hashes() -> TestResult {
    let table = entries(SMALL_LIST);
    let lines: Vec<String> = render(&table, "\n").lines().map(str::to_owned).collect();
    let dir = tempfile::tempdir()?;
    let target_sets = [vec![], vec![nt(ZERO)], table.iter().map(|entry| nt(entry.0)).collect()];
    (0..lines.len()).try_for_each(|index| -> TestResult {
        let damaged: String = lines
            .iter()
            .enumerate()
            .map(|(position, line)| if position == index { "x\n".to_owned() } else { format!("{line}\n") })
            .collect();
        let path = write_file(&dir, "damaged.txt", damaged.as_bytes())?;
        target_sets.iter().try_for_each(|targets| -> TestResult {
            assert!(matches!(open_list(&path, targets), Err(ListError::Malformed)), "line {index}");
            Ok(())
        })
    })
}


#[test]
fn an_unsorted_list_is_refused_and_a_sorted_one_summed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let reversed: Vec<_> = table.iter().rev().copied().collect();
    let bad = open_list(&write_file(&dir, "bad.txt", render(&reversed, "\n").as_bytes())?, &[]);
    assert!(matches!(bad, Err(ListError::Unsorted { .. })));
    let rendered = render(&table, "\n");
    let good = open_list(&write_file(&dir, "good.txt", rendered.as_bytes())?, &[])?;
    assert_eq!(good.size, rendered.len() as u64);
    assert_eq!(good.lines, table.len() as u64);
    assert_eq!(good.sha256, HEXLOWER.encode(Sha256::digest(rendered.as_bytes()).as_slice()));
    Ok(())
}


#[test]
fn an_unsorted_block_between_any_two_lines_is_refused() -> TestResult {
    let table = entries(SMALL_LIST);
    let dir = tempfile::tempdir()?;
    (1..table.len()).try_for_each(|index| -> TestResult {
        let mut swapped = table.clone();
        swapped.swap(index - 1, index);
        let path = write_file(&dir, "swapped.txt", render(&swapped, "\n").as_bytes())?;
        assert!(matches!(open_list(&path, &[]), Err(ListError::Unsorted { .. })), "swap at {index}");
        Ok(())
    })
}


#[test]
fn the_pass_reports_a_failing_or_short_reader() -> TestResult {
    assert!(matches!(scan(&mut FailingReader, 1, MAX_LINES, &[]), Err(ListError::Read { .. })));
    let line = render(&entries(1), "\n");
    let mut short = line.as_bytes();
    assert!(matches!(scan(&mut short, line.len() as u64 + 1, MAX_LINES, &[]), Err(ListError::Changed)));
    let mut whole = line.as_bytes();
    assert_eq!(scan(&mut whole, line.len() as u64, MAX_LINES, &[])?.lines, 1);
    let mut nothing: &[u8] = b"";
    let two = render(&entries(SMALL_LIST), "\n");
    let mut capped = two.as_bytes();
    assert!(matches!(scan(&mut capped, two.len() as u64, 1, &[]), Err(ListError::TooManyLines)));
    assert!(matches!(scan(&mut nothing, 0, MAX_LINES, &[]), Err(ListError::NoLines)));
    Ok(())
}


#[test]
fn a_line_is_judged_with_its_terminator_and_its_order() -> TestResult {
    let hash = nt(ZERO);
    let higher = nt(plus_one(ZERO));
    let line = format!("{}:1", "00".repeat(HASH_BYTES));
    assert!(matches!(read_entry(b"", None, 0), Err(ListError::Changed)));
    assert!(read_entry(format!("{line}\n").as_bytes(), None, 0).is_ok());
    assert!(read_entry(format!("{line}\r\n").as_bytes(), None, 0).is_ok());
    assert!(matches!(read_entry(line.as_bytes(), None, 0), Err(ListError::Unterminated)));
    assert!(matches!(read_entry(&[b'A'; OVERLONG_LINE], None, 0), Err(ListError::LineTooLong)));
    assert!(matches!(
        read_entry(format!("{line}\n").as_bytes(), Some(&hash), 0),
        Err(ListError::Unsorted { offset: 0 })
    ));
    assert!(matches!(
        read_entry(format!("{line}\n").as_bytes(), Some(&higher), 0),
        Err(ListError::Unsorted { .. })
    ));
    Ok(())
}


#[test]
fn a_list_owned_by_another_user_or_writable_by_others_is_refused() -> TestResult {
    let name = "list";
    assert!(judge_list(name, READABLE, OTHER_USER, OTHER_USER).is_ok());
    assert!(judge_list(name, READABLE, 0, OTHER_USER).is_ok());
    assert!(judge_list(name, OWNER_ONLY, OTHER_USER, OTHER_USER).is_ok());
    assert!(matches!(
        judge_list(name, READABLE, OTHER_USER, OTHER_USER + 1),
        Err(ListError::Untrusted(_))
    ));
    assert!(matches!(
        judge_list(name, WORLD_WRITABLE, OTHER_USER, OTHER_USER),
        Err(ListError::Writable { .. })
    ));
    assert!(matches!(
        judge_list(name, GROUP_WRITABLE, OTHER_USER, OTHER_USER),
        Err(ListError::Writable { .. })
    ));
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&entries(SMALL_LIST), "\n").as_bytes())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(WORLD_WRITABLE))?;
    let refused = open_list(&path, &[]).err().ok_or("accepted")?;
    assert!(matches!(refused, ListError::Writable { .. }));
    assert!(refused.to_string().contains("writable by group or other"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(READABLE))?;
    assert!(open_list(&path, &[]).is_ok());
    Ok(())
}


#[test]
fn errors_never_print_the_line_or_its_hash() -> TestResult {
    let table = entries(LIST_LINES);
    let first = table.first().ok_or("empty")?;
    let hash_text = render(&[*first], "").split(':').next().ok_or("no hash")?.to_owned();
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "bad.txt", format!("{hash_text}:12x\n").as_bytes())?;
    let error = open_list(&path, &[]).err().ok_or("expected an error")?;
    let rendered = format!("{error} {error:?}").to_uppercase();
    assert!(!rendered.contains(&hash_text));
    assert!(matches!(error, ListError::Malformed));
    Ok(())
}


#[test]
fn a_list_shrunk_after_the_open_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path, &[])?;
    verify_unchanged(&list)?;
    OpenOptions::new().write(true).open(&path)?.set_len(list.size / HALF)?;
    assert!(matches!(verify_unchanged(&list), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_grown_after_the_open_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path, &[])?;
    let mut grown = OpenOptions::new().append(true).open(&path)?;
    io::Write::write_all(&mut grown, b"garbage without hash\n")?;
    assert!(matches!(verify_unchanged(&list), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_rewritten_in_place_with_the_same_size_and_write_time_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let text = render(&table, "\n");
    let path = write_file(&dir, "list.txt", text.as_bytes())?;
    let list = open_list(&path, &[])?;
    verify_unchanged(&list)?;
    let written = std::fs::metadata(&path)?.modified()?;
    std::thread::sleep(CLOCK_TICK);
    let mut rewrite = OpenOptions::new().write(true).truncate(true).open(&path)?;
    io::Write::write_all(&mut rewrite, text.to_lowercase().as_bytes())?;
    rewrite.set_modified(written)?;
    assert_eq!(std::fs::metadata(&path)?.len(), list.size);
    assert_eq!(std::fs::metadata(&path)?.modified()?, written);
    assert!(matches!(verify_unchanged(&list), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_replaced_by_a_larger_one_over_the_same_path_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path, &[])?;
    std::thread::sleep(CLOCK_TICK);
    let bigger = entries(LIST_LINES + LIST_LINES);
    std::fs::write(&path, render(&bigger, "\n").as_bytes())?;
    assert!(matches!(verify_unchanged(&list), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_failing_fstat_is_a_read_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let list = open_list(&write_file(&dir, "list.txt", render(&entries(1), "\n").as_bytes())?, &[])?;
    assert!(matches!(verify_unchanged_with(&list, failing_inspect), Err(ListError::Read { .. })));
    Ok(())
}


#[test]
fn an_empty_list_or_one_without_a_valid_line_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(open_list(&write_file(&dir, "empty.txt", b"")?, &[]), Err(ListError::NoLines)));
    assert!(matches!(
        open_list(&write_file(&dir, "newlines.txt", b"\n\n\n")?, &[]),
        Err(ListError::Malformed)
    ));
    assert!(matches!(
        open_list(&write_file(&dir, "malformed.txt", b"not a line\n")?, &[]),
        Err(ListError::Malformed)
    ));
    Ok(())
}
