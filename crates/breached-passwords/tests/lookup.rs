#[path = "support/files.rs"]
mod files;
#[path = "support/table.rs"]
mod table;
#[path = "support/types.rs"]
mod types;


use breached_passwords::error::ListError;
use breached_passwords::list::{check_order, check_order_with, lookup, lookup_many, lookup_probed, lookup_with, open_list, read_at};
use breached_passwords::model::{NtHash, HALVES, HASH_BYTES, HASH_HEX_LEN, MAX_PROBES, WINDOW_BYTES};
use files::write_file;
use std::fs::{File, OpenOptions};
use std::io;
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


fn failing_read(_: &File, _: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(io::Error::other("injected"))
}


#[test]
fn every_present_hash_is_found_with_its_count() -> TestResult {
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
    let checked = check_order_with(&list, failing_read);
    assert!(matches!(checked, Err(ListError::Read { .. })));
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
fn hostile_lists_are_refused_with_offsets() -> TestResult {
    let table = entries(LIST_LINES);
    let first = table.first().ok_or("empty")?;
    let hash_text = render(&[*first], "");
    let dir = tempfile::tempdir()?;
    let target = nt(ZERO);
    let overlong = "A".repeat(OVERLONG_LINE);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("unterminated", hash_text.clone().into_bytes()),
        ("overlong", format!("{overlong}\n").into_bytes()),
        ("overlong_without_newline", overlong.into_bytes()),
        ("not_hex", format!("{}:5\n", "Z".repeat(HASH_HEX_LEN)).into_bytes()),
        ("separators", "\n".repeat(OVERLONG_LINE).into_bytes()),
    ];
    cases.iter().try_for_each(|(name, content)| -> TestResult {
        let path = write_file(&dir, name, content)?;
        let list = open_list(&path)?;
        let result = lookup(&list, &target);
        assert!(result.is_err(), "{name}");
        Ok(())
    })
}


#[test]
fn an_unsorted_list_is_refused_and_a_sorted_one_sampled() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let reversed: Vec<_> = table.iter().rev().copied().collect();
    let bad = open_list(&write_file(&dir, "bad.txt", render(&reversed, "\n").as_bytes())?)?;
    assert!(matches!(check_order(&bad), Err(ListError::Unsorted { .. })));
    let rendered = render(&table, "\n");
    let good = open_list(&write_file(&dir, "good.txt", rendered.as_bytes())?)?;
    let info = check_order(&good)?;
    assert_eq!(info.bytes, rendered.len() as u64);
    assert!(info.lines_checked > 0);
    Ok(())
}


#[test]
fn errors_never_print_the_line_or_its_hash() -> TestResult {
    let table = entries(LIST_LINES);
    let first = table.first().ok_or("empty")?;
    let hash_text = render(&[*first], "").split(':').next().ok_or("no hash")?.to_owned();
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "bad.txt", format!("{hash_text}:12x\n").as_bytes())?;
    let list = open_list(&path)?;
    let error = lookup(&list, &nt(ZERO)).err().ok_or("expected an error")?;
    let rendered = format!("{error} {error:?}").to_uppercase();
    assert!(!rendered.contains(&hash_text));
    assert!(matches!(error, ListError::Malformed { .. }));
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
    assert!(matches!(
        lookup_with(&list, &nt(ZERO), MAX_PROBES, short_read),
        Err(ListError::Changed { .. })
    ));
    assert!(matches!(check_order_with(&list, short_read), Err(ListError::Changed { .. })));
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
    assert!(matches!(lookup(&list, &nt(last)), Err(ListError::Changed { .. })));
    assert!(matches!(check_order(&list), Err(ListError::Changed { .. })));
    Ok(())
}


#[test]
fn a_list_grown_while_open_is_read_up_to_the_recorded_size() -> TestResult {
    let table = entries(LIST_LINES);
    let dir = tempfile::tempdir()?;
    let path = write_file(&dir, "list.txt", render(&table, "\n").as_bytes())?;
    let list = open_list(&path)?;
    let mut grown = OpenOptions::new().append(true).open(&path)?;
    io::Write::write_all(&mut grown, b"garbage without hash\n")?;
    let last = table.last().map(|entry| entry.0).ok_or("empty")?;
    assert!(lookup(&list, &nt(last))?.compromised);
    assert!(!lookup(&list, &nt([u8::MAX; HASH_BYTES]))?.compromised);
    Ok(())
}


#[test]
fn an_empty_list_or_one_without_a_valid_line_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let empty = open_list(&write_file(&dir, "empty.txt", b"")?)?;
    assert!(matches!(check_order(&empty), Err(ListError::NoLines)));
    let newlines = open_list(&write_file(&dir, "newlines.txt", b"\n\n\n")?)?;
    assert!(check_order(&newlines).is_err());
    let malformed = open_list(&write_file(&dir, "malformed.txt", b"not a line\n")?)?;
    assert!(matches!(check_order(&malformed), Err(ListError::Malformed { .. })));
    Ok(())
}
