#[path = "common/types.rs"]
mod types;


use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use types::TestResult;
use vuln_match::error::FeedError;
use vuln_match::feed::{default_limits, is_safe_name, licence_of, load_feed, load_feed_reader};
use vuln_match::limits::{MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_TOTAL_BYTES, RATIO_FLOOR_BYTES};
use vuln_match::model::{FeedLimits, FeedSettings};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};


const RECORD_BYTES: usize = 4096;


const LOCAL_HEADER_BYTES: usize = 30;


const SMALL_ENTRY: u64 = 10;


const SMALL_ARCHIVE: u64 = 10;


const SMALL_RATIO: u64 = 2;


const SMALL_FLOOR: u64 = 16;


const ZERO_BYTES: usize = 100_000;


const CORRUPT_BYTE: u8 = 255;


const CORRUPT_SPAN: usize = 4;


const BAD_ENTRIES: usize = 2;


const TOTAL_FACTOR: u64 = 2;


const TWO_ENTRIES: usize = 2;


const MAGIC_BYTES: usize = 4;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected"))
    }
}


fn build_zip(entries: &[(&str, &[u8])], method: CompressionMethod) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(method);
    entries.iter().try_for_each(|(name, content)| -> Result<(), Box<dyn std::error::Error>> {
        writer.start_file(*name, options)?;
        writer.write_all(content)?;
        Ok(())
    })?;
    Ok(writer.finish()?.into_inner())
}


fn settings_for(bytes: &[u8]) -> FeedSettings {
    FeedSettings {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        ..FeedSettings::default()
    }
}


fn load(bytes: &[u8], limits: &FeedLimits) -> Result<vuln_match::model::FeedReport, FeedError> {
    load_feed_reader(bytes, &settings_for(bytes), limits)
}


fn record(id: &str) -> String {
    format!(r#"{{"id":"{id}"}}"#)
}


#[test]
fn records_are_loaded_with_licences_and_bad_entries_counted() -> TestResult {
    let ghsa = record("GHSA-1");
    let dsa = record("DSA-1");
    let bytes = build_zip(
        &[
            ("dir/", b""),
            ("a.json", ghsa.as_bytes()),
            ("b.json", dsa.as_bytes()),
            ("bad.json", b"not json"),
            ("binary.json", &[CORRUPT_BYTE, CORRUPT_BYTE]),
        ],
        CompressionMethod::Deflated,
    )?;
    let mut settings = settings_for(&bytes);
    settings.default_licence = "CC0-1.0".into();
    settings.prefix_licences = BTreeMap::from([("GHSA-".to_string(), "CC-BY-4.0".to_string())]);
    let report = load_feed_reader(bytes.as_slice(), &settings, &default_limits())?;
    let loaded: Vec<(&str, &str)> = report
        .records
        .iter()
        .map(|loaded| (loaded.record.id.as_str(), loaded.licence.as_str()))
        .collect();
    assert_eq!(loaded, vec![("GHSA-1", "CC-BY-4.0"), ("DSA-1", "CC0-1.0")]);
    assert_eq!(report.bad_entries, BAD_ENTRIES);
    assert_eq!(report.dropped_by_licence, 0);
    Ok(())
}


#[test]
fn denied_licence_drops_records() -> TestResult {
    let ghsa = record("GHSA-1");
    let dsa = record("DSA-1");
    let bytes = build_zip(&[("a.json", ghsa.as_bytes()), ("b.json", dsa.as_bytes())], CompressionMethod::Stored)?;
    let mut settings = settings_for(&bytes);
    settings.prefix_licences = BTreeMap::from([("GHSA-".to_string(), "CC-BY-NC-4.0".to_string())]);
    settings.denied_licences = vec!["CC-BY-NC-4.0".into()];
    let report = load_feed_reader(bytes.as_slice(), &settings, &default_limits())?;
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.dropped_by_licence, 1);
    assert_eq!(licence_of(&settings, "DSA-1"), "");
    Ok(())
}


#[test]
fn checksum_mismatch_refuses_the_file() -> TestResult {
    let bytes = build_zip(&[("a.json", record("A").as_bytes())], CompressionMethod::Stored)?;
    let mut settings = settings_for(&bytes);
    settings.sha256 = "00".into();
    let result = load_feed_reader(bytes.as_slice(), &settings, &default_limits());
    assert!(matches!(result, Err(FeedError::ChecksumMismatch { .. })));
    Ok(())
}


#[test]
fn checksum_is_case_insensitive() -> TestResult {
    let bytes = build_zip(&[("a.json", record("A").as_bytes())], CompressionMethod::Stored)?;
    let mut settings = settings_for(&bytes);
    settings.sha256 = format!(" {} ", settings.sha256.to_uppercase());
    assert_eq!(load_feed_reader(bytes.as_slice(), &settings, &default_limits())?.records.len(), 1);
    Ok(())
}


#[test]
fn zip_bomb_by_ratio_is_refused() -> TestResult {
    let zeros = vec![u8::MIN; ZERO_BYTES];
    let bytes = build_zip(&[("a.json", &zeros)], CompressionMethod::Deflated)?;
    let limits = FeedLimits {
        max_entry_bytes: MAX_ENTRY_BYTES,
        ratio_floor_bytes: SMALL_FLOOR,
        max_ratio: SMALL_RATIO,
        ..default_limits()
    };
    assert!(matches!(load(&bytes, &limits), Err(FeedError::RatioExceeded { .. })));
    Ok(())
}


#[test]
fn ratio_below_the_floor_is_tolerated() -> TestResult {
    let padded = format!(r#"{{"id":"A","aliases":[{}]}}"#, vec![r#""x""#; RECORD_BYTES].join(","));
    let bytes = build_zip(&[("a.json", padded.as_bytes())], CompressionMethod::Deflated)?;
    let limits = FeedLimits {
        max_ratio: SMALL_RATIO,
        ..default_limits()
    };
    assert_eq!(load(&bytes, &limits)?.records.len(), 1);
    Ok(())
}


#[test]
fn zip_bomb_by_total_size_is_refused() -> TestResult {
    let content = record("A");
    let bytes = build_zip(
        &[
            ("a.json", content.as_bytes()),
            ("b.json", content.as_bytes()),
            ("c.json", content.as_bytes()),
        ],
        CompressionMethod::Stored,
    )?;
    let limits = FeedLimits {
        max_total_bytes: content.len() as u64 * TOTAL_FACTOR,
        ..default_limits()
    };
    assert!(matches!(load(&bytes, &limits), Err(FeedError::TotalTooLarge { .. })));
    Ok(())
}


#[test]
fn oversized_entry_is_refused() -> TestResult {
    let bytes = build_zip(&[("a.json", record("A-long-identifier").as_bytes())], CompressionMethod::Stored)?;
    let limits = FeedLimits {
        max_entry_bytes: SMALL_ENTRY,
        ..default_limits()
    };
    assert!(matches!(load(&bytes, &limits), Err(FeedError::EntryTooLarge { .. })));
    Ok(())
}


#[test]
fn oversized_archive_and_too_many_entries_are_refused() -> TestResult {
    let bytes = build_zip(
        &[("a.json", record("A").as_bytes()), ("b.json", record("B").as_bytes())],
        CompressionMethod::Stored,
    )?;
    let small_archive = FeedLimits {
        max_archive_bytes: SMALL_ARCHIVE,
        ..default_limits()
    };
    assert!(matches!(load(&bytes, &small_archive), Err(FeedError::ArchiveTooLarge { .. })));
    let one_entry = FeedLimits {
        max_entries: 1,
        ..default_limits()
    };
    assert!(matches!(
        load(&bytes, &one_entry),
        Err(FeedError::TooManyEntries { count: TWO_ENTRIES, max: 1 })
    ));
    Ok(())
}


#[test]
fn unsafe_entry_names_are_refused() -> TestResult {
    [
        "../evil.json",
        "/abs.json",
        "a/../b.json",
        "a\\..\\b.json",
        "\\abs.json",
        "C:evil.json",
        "nul\0.json",
    ]
    .iter()
    .try_for_each(|name| -> TestResult {
        let bytes = build_zip(&[(name, record("A").as_bytes())], CompressionMethod::Stored)?;
        assert!(matches!(load(&bytes, &default_limits()), Err(FeedError::UnsafeName { .. })), "{name:?}");
        Ok(())
    })?;
    assert!(is_safe_name(b"all/GHSA-1.json") && is_safe_name(b"a..b.json") && !is_safe_name(b".."));
    Ok(())
}


#[test]
fn read_and_format_failures_are_reported() -> TestResult {
    assert!(matches!(
        load_feed_reader(Failing, &FeedSettings::default(), &default_limits()),
        Err(FeedError::Io(_))
    ));
    assert!(matches!(
        load_feed(Path::new("/nonexistent/all.zip"), &FeedSettings::default(), &default_limits()),
        Err(FeedError::Io(_))
    ));
    assert!(matches!(load(b"not a zip", &default_limits()), Err(FeedError::Zip(_))));
    Ok(())
}


#[test]
fn corrupt_entries_are_reported() -> TestResult {
    let text = record("A");
    let mut header = build_zip(&[("a.json", text.as_bytes())], CompressionMethod::Stored)?;
    header.iter_mut().take(MAGIC_BYTES).for_each(|byte| *byte = u8::MIN);
    assert!(matches!(load(&header, &default_limits()), Err(FeedError::Zip(_))));
    let padded = format!(r#"{{"id":"A","aliases":[{}]}}"#, vec![r#""abcdef""#; RECORD_BYTES].join(","));
    let mut data = build_zip(&[("a.json", padded.as_bytes())], CompressionMethod::Deflated)?;
    data.iter_mut()
        .skip(LOCAL_HEADER_BYTES + "a.json".len())
        .take(CORRUPT_SPAN)
        .for_each(|byte| *byte = CORRUPT_BYTE);
    let outcome = load(&data, &default_limits());
    assert!(matches!(outcome, Err(FeedError::Io(_))), "{outcome:?}");
    Ok(())
}


#[test]
fn feed_is_loaded_from_a_file() -> TestResult {
    let bytes = build_zip(&[("a.json", record("A").as_bytes())], CompressionMethod::Stored)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("all.zip");
    std::fs::write(&path, &bytes)?;
    assert_eq!(load_feed(&path, &settings_for(&bytes), &default_limits())?.records.len(), 1);
    Ok(())
}


#[test]
fn default_limits_use_the_named_constants() -> TestResult {
    let limits = default_limits();
    assert_eq!(limits.max_archive_bytes, MAX_ARCHIVE_BYTES);
    assert_eq!(limits.max_entries, MAX_ARCHIVE_ENTRIES);
    assert_eq!(limits.max_entry_bytes, MAX_ENTRY_BYTES);
    assert_eq!(limits.max_total_bytes, MAX_TOTAL_BYTES);
    assert_eq!(limits.max_ratio, MAX_COMPRESSION_RATIO);
    assert_eq!(limits.ratio_floor_bytes, RATIO_FLOOR_BYTES);
    Ok(())
}
