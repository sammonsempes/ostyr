#![cfg(unix)]


#[path = "support/files.rs"]
mod files;
#[path = "support/table.rs"]
mod table;
#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::list::{
    judge_list, lookup, lookup_many, lookup_probed, lookup_with, open_list, read_at, read_entry, scan, verify_unchanged, verify_unchanged_with,
};
use breached_passwords::model::{NtHash, HALVES, HASH_BYTES, HASH_HEX_LEN, MAX_PROBES, WINDOW_BYTES};
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


fn nt(bytes: [u8; HASH_BYTES]) -> NtHash {
    NtHash(Zeroizing::new(bytes))
}


fn plus_one(hash: [u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    u128::from_be_bytes(hash).wrapping_add(1).to_be_bytes()
}


const OVERLONG_LINE: usize = 1000;


const LISTED_FAILURES: usize = 4;


const WORLD_WRITABLE: u32 = 0o666;


const GROUP_WRITABLE: u32 = 0o664;


const READABLE: u32 = 0o644;


const OWNER_ONLY: u32 = 0o600;


const OTHER_USER: u32 = 1000;


const SMALL_LIST: usize = 200;


const MAX_LINES: u64 = 1_000;


const CLOCK_TICK: Duration = Duration::from_millis(50);


fn failing_inspect(_: &File) -> io::Result<Metadata> {
    Err(io::Error::other("injected"))
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


fn failing_read(_: &File, _: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(io::Error::other("injected"))
}


#[test]
fn every_present_hash_is_found() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    LINE_ENDINGS.iter().try_for_each(|eol| -> TestResult {
        let path = write_file(&dir, "list.txt", render(&table, eol).as_bytes())?;
        let list = open_list(&path)?;
        table.iter().try_for_each(|(hash, count)| -> TestResult {
            let probed = lookup_probed(&list, &nt(*hash))?;
            assert!(probed.verdict.compromised);
            assert!(*count > 0);
            assert!(probed.probes <= MAX_PROBES);
            Ok(())
        })
    })
}


#[test]
fn absent_hashes_are_not_found() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let first = table.first().map(|entry| entry.0).ok_or("empty")?;
    let last = table.last().map(|entry| entry.0).ok_or("empty")?;
    let before = ZERO;
    let after = [u8::MAX; HASH_BYTES];
    let between = plus_one(first);
    assert!(!table.iter().any(|entry| entry.0 == between));
    let probed = [before, between, plus_one(last), after].map(|hash| lookup_probed(&list, &nt(hash)));
    probed.into_iter().try_for_each(|result| -> TestResult {
        let found = result?;
        assert!(!found.verdict.compromised);
        assert!(found.probes <= MAX_PROBES);
        Ok(())
    })
}


#[test]
fn a_batch_is_answered_in_input_order() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let first = table.first().ok_or("empty")?;
    let verdicts = lookup_many(&list, &[nt(ZERO), nt(first.0)])?;
    assert!(!verdicts.first().ok_or("none")?.compromised);
    assert!(verdicts.get(1).ok_or("none")?.compromised);
    assert!(lookup(&list, &nt(first.0))?.compromised);
    Ok(())
}


#[test]
fn a_probe_limit_is_a_typed_error() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let result = lookup_with(&list, &nt(ZERO), 1, read_at);
    assert!(matches!(result, Err(ListError::ProbeLimit)));
    Ok(())
}


#[test]
fn a_failing_read_is_a_typed_error_with_its_cause() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let looked = lookup_with(&list, &nt(ZERO), MAX_PROBES, failing_read);
    assert!(matches!(looked, Err(ListError::Read { .. })));
    Ok(())
}


#[test]
fn read_at_reports_seek_and_read_failures() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", b"x")?;
    let readable = File::open(&path)?;
    assert!(read_at(&readable, u64::MAX).is_err());
    let write_only = OpenOptions::new().write(true).open(&path)?;
    assert!(read_at(&write_only, 0).is_err());
    assert!(read_at(&readable, 0)?.len() as u64 <= WINDOW_BYTES);
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
        assert!(open_list(&path).is_err(), "{name}");
        Ok(())
    })
}


#[test]
fn a_malformed_line_anywhere_fails_the_open_whatever_the_hashes() -> TestResult {
    let table = entries(SMALL_LIST);
    let lines: Vec<String> = render(&table, "\n").lines().map(str::to_owned).collect();
    let dir = tempfile::tempdir()?;
    (0..lines.len()).try_for_each(|index| -> TestResult {
        let damaged: String = lines
            .iter()
            .enumerate()
            .map(|(position, line)| if position == index { "x\n".to_owned() } else { format!("{line}\n") })
            .collect();
        let path = write_file(&dir, "damaged.txt", damaged.as_bytes())?;
        assert!(matches!(open_list(&path), Err(ListError::Malformed)), "line {index}");
        Ok(())
    })
}


#[test]
fn an_unsorted_list_is_refused_and_a_sorted_one_summed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let reversed: Vec<_> = table.iter().rev().copied().collect();
    let bad = open_list(&write_file(&dir, "bad.txt", render(&reversed, "\n").as_bytes())?);
    assert!(matches!(bad, Err(ListError::Unsorted { .. })));
    let rendered = render(&table, "\n");
    let good = open_list(&write_file(&dir, "good.txt", rendered.as_bytes())?)?;
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
        assert!(matches!(open_list(&path), Err(ListError::Unsorted { .. })), "swap at {index}");
        Ok(())
    })
}


#[test]
fn the_pass_reports_a_failing_or_short_reader() -> TestResult {
    assert!(matches!(scan(&mut FailingReader, 1, MAX_LINES), Err(ListError::Read { .. })));
    let line = render(&entries(1), "\n");
    let mut short = line.as_bytes();
    assert!(matches!(scan(&mut short, line.len() as u64 + 1, MAX_LINES), Err(ListError::Changed)));
    let mut whole = line.as_bytes();
    assert_eq!(scan(&mut whole, line.len() as u64, MAX_LINES)?.lines, 1);
    let mut nothing: &[u8] = b"";
    let two = render(&entries(SMALL_LIST), "\n");
    let mut capped = two.as_bytes();
    assert!(matches!(scan(&mut capped, two.len() as u64, 1), Err(ListError::TooManyLines)));
    assert!(matches!(scan(&mut nothing, 0, MAX_LINES), Err(ListError::NoLines)));
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
        Err(ListError::Untrusted(_))
    ));
    assert!(matches!(
        judge_list(name, GROUP_WRITABLE, OTHER_USER, OTHER_USER),
        Err(ListError::Untrusted(_))
    ));
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&entries(SMALL_LIST), "\n").as_bytes())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(matches!(open_list(&path), Err(ListError::Untrusted(_))));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(READABLE))?;
    assert!(open_list(&path).is_ok());
    Ok(())
}


#[test]
fn errors_never_print_the_line_or_its_hash() -> TestResult {
    let table = entries(LIST_LINES);
    let first = table.first().ok_or("empty")?;
    let hash_text = render(&[*first], "").split(':').next().ok_or("no hash")?.to_owned();
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "bad.txt", format!("{hash_text}:12x\n").as_bytes())?;
    let error = open_list(&path).err().ok_or("expected an error")?;
    let rendered = format!("{error} {error:?}").to_uppercase();
    assert!(!rendered.contains(&hash_text));
    assert!(matches!(error, ListError::Malformed));
    Ok(())
}


fn short_read(_: &File, _: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(Vec::new()))
}


#[test]
fn a_short_read_is_a_changed_list_not_an_end_of_file() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    assert!(matches!(lookup_with(&list, &nt(ZERO), MAX_PROBES, short_read), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_shrunk_while_open_fails_instead_of_reporting_clean() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let last = table.last().map(|entry| entry.0).ok_or("empty")?;
    assert!(lookup(&list, &nt(last))?.compromised);
    OpenOptions::new().write(true).open(&path)?.set_len(list.size / HALVES)?;
    assert!(matches!(lookup(&list, &nt(last)), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_grown_while_open_is_changed_not_read_up_to_the_old_size() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let mut grown = OpenOptions::new().append(true).open(&path)?;
    io::Write::write_all(&mut grown, b"garbage without hash\n")?;
    let last = table.last().map(|entry| entry.0).ok_or("empty")?;
    assert!(matches!(lookup(&list, &nt(last)), Err(ListError::Changed)));
    assert!(matches!(lookup_many(&list, &[nt(last)]), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_rewritten_in_place_with_the_same_size_and_write_time_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let text = render(&table, "\n");
    let path = write_file(&dir, "list.txt", text.as_bytes())?;
    let list = open_list(&path)?;
    let last = table.last().map(|entry| entry.0).ok_or("empty")?;
    assert!(lookup(&list, &nt(last))?.compromised);
    verify_unchanged(&list)?;
    let written = std::fs::metadata(&path)?.modified()?;
    std::thread::sleep(CLOCK_TICK);
    let mut rewrite = OpenOptions::new().write(true).truncate(true).open(&path)?;
    io::Write::write_all(&mut rewrite, text.to_lowercase().as_bytes())?;
    rewrite.set_modified(written)?;
    assert_eq!(std::fs::metadata(&path)?.len(), list.size);
    assert_eq!(std::fs::metadata(&path)?.modified()?, written);
    assert!(matches!(verify_unchanged(&list), Err(ListError::Changed)));
    assert!(matches!(lookup(&list, &nt(last)), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_list_replaced_by_a_larger_one_over_the_same_path_is_changed() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let hashes: Vec<NtHash> = table.iter().map(|entry| nt(entry.0)).collect();
    std::thread::sleep(CLOCK_TICK);
    let bigger = entries(LIST_LINES + LIST_LINES);
    std::fs::write(&path, render(&bigger, "\n").as_bytes())?;
    assert!(matches!(lookup_many(&list, &hashes), Err(ListError::Changed)));
    Ok(())
}


#[test]
fn a_failing_fstat_is_a_read_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let list = open_list(&write_file(&dir, "list.txt", render(&entries(1), "\n").as_bytes())?)?;
    assert!(matches!(verify_unchanged_with(&list, failing_inspect), Err(ListError::Read { .. })));
    Ok(())
}


fn longest_digit_run(text: &str) -> usize {
    text.split(|character: char| !character.is_ascii_digit())
        .map(str::len)
        .fold(0, usize::max)
}


#[test]
fn no_lookup_error_carries_an_offset() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let rendered = render(&table, "\n");
    let path = write_file(&dir, "list.txt", rendered.as_bytes())?;
    let list = open_list(&path)?;
    let size_digits = list.size.to_string().len();
    let mut errors: Vec<ListError> = Vec::new();
    errors.extend(lookup_with(&list, &nt(ZERO), 1, read_at).err());
    errors.extend(lookup_with(&list, &nt(ZERO), MAX_PROBES, failing_read).err());
    errors.extend(lookup_with(&list, &nt(ZERO), MAX_PROBES, short_read).err());
    OpenOptions::new().write(true).open(&path)?.set_len(list.size / HALVES)?;
    errors.extend(lookup(&list, &nt(ZERO)).err());
    assert_eq!(errors.len(), LISTED_FAILURES);
    errors.iter().for_each(|error| {
        let text = format!("{error} {error:?}");
        assert!(longest_digit_run(&text) < size_digits.min(OVERLONG_LINE.to_string().len()), "{text}");
    });
    Ok(())
}


#[test]
fn an_empty_list_or_one_without_a_valid_line_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(open_list(&write_file(&dir, "empty.txt", b"")?), Err(ListError::NoLines)));
    assert!(matches!(
        open_list(&write_file(&dir, "newlines.txt", b"\n\n\n")?),
        Err(ListError::Malformed)
    ));
    assert!(matches!(
        open_list(&write_file(&dir, "malformed.txt", b"not a line\n")?),
        Err(ListError::Malformed)
    ));
    Ok(())
}
