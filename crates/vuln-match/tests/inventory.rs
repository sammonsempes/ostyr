#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;
use vuln_match::inventory::{
    accepted, asset_of, list_inventory, list_inventory_capped, loggable, parse_inventory_capped, read_inventory, read_inventory_capped,
    InventoryError, MAX_LOGGED_REFUSALS,
};


const ONE_PACKAGE: &str = r#"[{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-10"}]"#;


const SMALL_PACKAGES: usize = 2;


const SMALL_BYTES: u64 = 16;


const SMALL_FILES: usize = 3;


const MIDDLE_FILES: usize = 10;


const HALF_MIDDLE: usize = 5;


const FILLER: usize = 5;


const LONG_NAME: usize = 300;


const INVALID_UTF8: u8 = 255;


const REFUSED_NAMES: usize = 7;


fn debian(name: &str, version: &str) -> String {
    format!(r#"{{"ecosystem":"Debian:12","name":"{name}","version":"{version}"}}"#)
}


#[test]
fn asset_names_follow_the_store_grammar() -> TestResult {
    assert_eq!(asset_of(OsStr::new("host-1.json")), Some("host-1".to_owned()));
    assert_eq!(asset_of(OsStr::new("a.b_c.json")), Some("a.b_c".to_owned()));
    [
        "host.txt",
        ".json",
        "-x.json",
        "..json",
        ".hidden.json",
        "a b.json",
        "h\u{e9}.json",
        "a\u{0}b.json",
        "x.json.bak",
    ]
    .iter()
    .for_each(|name| assert_eq!(asset_of(OsStr::new(name)), None, "{name}"));
    assert_eq!(asset_of(OsStr::new(&format!("{}.json", "a".repeat(LONG_NAME)))), None);
    assert_eq!(asset_of(OsStr::from_bytes(&[INVALID_UTF8, b'.', b'j', b's', b'o', b'n'])), None);
    Ok(())
}


#[test]
fn a_logged_name_is_printable_and_cut() -> TestResult {
    let shown = loggable(OsStr::new("a\u{1b}[31mb\n"));
    assert!(!shown.contains('\u{1b}') && !shown.contains('\n'), "{shown}");
    assert!(loggable(OsStr::new(&"z".repeat(LONG_NAME))).contains("[cut]"));
    Ok(())
}


#[test]
fn a_good_list_parses() -> TestResult {
    let packages = parse_inventory_capped(ONE_PACKAGE.as_bytes(), SMALL_PACKAGES)?;
    assert_eq!(packages.len(), 1);
    assert_eq!(packages.first().map(|package| package.name.as_str()), Some("curl"));
    assert!(parse_inventory_capped(b"[]", SMALL_PACKAGES)?.is_empty());
    Ok(())
}


#[test]
fn what_is_not_a_list_is_refused() -> TestResult {
    [&b"{}"[..], b"", b"nonsense", b"[1,", b"\"text\""]
        .iter()
        .for_each(|bytes| assert!(matches!(parse_inventory_capped(bytes, SMALL_PACKAGES), Err(InventoryError::NotList))));
    Ok(())
}


#[test]
fn the_count_comes_before_any_entry_is_parsed() -> TestResult {
    let invalid_entries = format!("[{}]", ["1"; FILLER].join(","));
    let error = parse_inventory_capped(invalid_entries.as_bytes(), SMALL_PACKAGES);
    assert!(
        matches!(
            error,
            Err(InventoryError::TooMany {
                count: FILLER,
                max: SMALL_PACKAGES
            })
        ),
        "{error:?}"
    );
    Ok(())
}


#[test]
fn a_bad_entry_refuses_the_whole_file() -> TestResult {
    let wrong_field = r#"[{"ecosystem":"Debian:12","name":"curl","version":"1","extra":1}]"#;
    let missing = r#"[{"ecosystem":"Debian:12","name":"curl"}]"#;
    let spaced = debian("a b", "1");
    let dashed = debian("-x", "1");
    let empty = debian("", "1");
    let bad_version = debian("curl", "1 2");
    let bad_ecosystem = r#"{"ecosystem":"Deb ian","name":"curl","version":"1"}"#;
    [
        wrong_field,
        missing,
        "[5]",
        "[[[[]]]]",
        spaced.as_str(),
        dashed.as_str(),
        empty.as_str(),
        bad_version.as_str(),
        bad_ecosystem,
    ]
    .iter()
    .for_each(|body| {
        let text = if body.starts_with('[') {
            (*body).to_owned()
        } else {
            format!("[{body}]")
        };
        let error = parse_inventory_capped(text.as_bytes(), SMALL_PACKAGES);
        assert!(matches!(error, Err(InventoryError::BadEntries { bad: 1 })), "{text}: {error:?}");
    });
    let mixed = format!("[{},5]", debian("curl", "1"));
    assert!(matches!(
        parse_inventory_capped(mixed.as_bytes(), SMALL_PACKAGES),
        Err(InventoryError::BadEntries { bad: 1 })
    ));
    Ok(())
}


#[test]
fn a_bad_entry_error_carries_no_document_text() -> TestResult {
    let secret = r#"[{"ecosystem":"Debian:12","name":"SECRET-MARKER","version":"a b"}]"#;
    let error = parse_inventory_capped(secret.as_bytes(), SMALL_PACKAGES)
        .err()
        .map(|found| format!("{found} {found:?}"));
    assert!(error.is_some_and(|text| !text.contains("SECRET-MARKER")));
    Ok(())
}


#[test]
fn a_file_is_read_through_the_capped_reader() -> TestResult {
    let dir = tempdir()?;
    let good = dir.path().join("a.json");
    fs::write(&good, ONE_PACKAGE)?;
    assert_eq!(read_inventory(&good)?.len(), 1);
    assert!(matches!(
        read_inventory_capped(&good, SMALL_BYTES, SMALL_PACKAGES),
        Err(InventoryError::Read(_))
    ));
    assert!(matches!(read_inventory(&dir.path().join("missing.json")), Err(InventoryError::Read(_))));
    assert!(matches!(read_inventory(dir.path()), Err(InventoryError::Read(_))));
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let fifo = dir.path().join("pipe.json");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    assert!(matches!(read_inventory(&fifo), Err(InventoryError::Read(_))));
    let listing = list_inventory(dir.path())?;
    assert!(listing.files.is_empty());
    assert_eq!(listing.refused, 1);
    Ok(())
}


#[test]
fn the_listing_keeps_regular_files_named_after_an_asset() -> TestResult {
    let dir = tempdir()?;
    fs::write(dir.path().join("b.json"), ONE_PACKAGE)?;
    fs::write(dir.path().join("a.json"), ONE_PACKAGE)?;
    fs::write(dir.path().join("notes.txt"), "x")?;
    fs::write(dir.path().join(".tmp.json"), "x")?;
    fs::write(dir.path().join("-flag.json"), "x")?;
    fs::write(dir.path().join("sp ace.json"), "x")?;
    fs::create_dir(dir.path().join("sub.json"))?;
    symlink("/etc/shadow", dir.path().join("link.json"))?;
    symlink(dir.path().join("a.json"), dir.path().join("alias.json"))?;
    let listing = list_inventory(dir.path())?;
    let assets: Vec<&str> = listing.files.iter().map(|(asset, _path)| asset.as_str()).collect();
    assert_eq!(assets, ["a", "b"]);
    assert_eq!(listing.refused, REFUSED_NAMES);
    assert_eq!((listing.left_out, listing.first_left_out), (0, None));
    Ok(())
}


#[test]
fn a_directory_over_the_cap_is_sorted_then_cut_and_the_first_left_out_is_named() -> TestResult {
    let dir = tempdir()?;
    let creation: Vec<String> = (0..MIDDLE_FILES)
        .map(|index| format!("m{index:02}"))
        .take(HALF_MIDDLE)
        .chain((0..SMALL_FILES).map(|index| format!("a{index}")))
        .chain((0..MIDDLE_FILES).map(|index| format!("m{index:02}")).skip(HALF_MIDDLE))
        .collect();
    creation
        .iter()
        .try_for_each(|name| fs::write(dir.path().join(format!("{name}.json")), ONE_PACKAGE))?;
    let listing = list_inventory_capped(dir.path(), SMALL_FILES)?;
    let assets: Vec<&str> = listing.files.iter().map(|(asset, _path)| asset.as_str()).collect();
    assert_eq!(assets, ["a0", "a1", "a2"]);
    assert_eq!(listing.left_out, MIDDLE_FILES);
    assert_eq!(listing.first_left_out.as_deref(), Some("m00"));
    let exact = list_inventory_capped(dir.path(), SMALL_FILES + MIDDLE_FILES)?;
    assert_eq!(
        (exact.left_out, exact.first_left_out, exact.files.len()),
        (0, None, SMALL_FILES + MIDDLE_FILES)
    );
    Ok(())
}


#[test]
fn refusals_past_the_logging_limit_are_still_counted() -> TestResult {
    let dir = tempdir()?;
    (0..=MAX_LOGGED_REFUSALS).try_for_each(|index| fs::write(dir.path().join(format!("note{index}.txt")), "x"))?;
    fs::write(dir.path().join("a.json"), ONE_PACKAGE)?;
    let listing = list_inventory(dir.path())?;
    assert_eq!((listing.refused, listing.files.len()), (MAX_LOGGED_REFUSALS + 1, 1));
    Ok(())
}


#[test]
fn an_unreadable_directory_is_an_error() -> TestResult {
    assert!(matches!(
        list_inventory(Path::new("/nonexistent-vuln-inventory")),
        Err(InventoryError::Directory(_))
    ));
    Ok(())
}


#[test]
fn an_entry_that_could_not_be_read_is_refused() -> TestResult {
    assert_eq!(accepted(Err(io::Error::other("injected")), true), None);
    assert_eq!(accepted(Err(io::Error::other("injected")), false), None);
    Ok(())
}
