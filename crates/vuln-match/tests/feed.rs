#[path = "common/types.rs"]
mod types;


use flate2::write::DeflateEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use types::TestResult;
use vuln_match::error::FeedError;
use vuln_match::feed::{default_limits, is_safe_name, licence_of, load_feed, load_feed_reader, parse_local, retained_items, take_bytes};
use vuln_match::limits::{
    DESCRIPTOR_FLAG, DESCRIPTOR_SIGNATURE, ENCRYPTED_FLAG, EOCD_SIGNATURE, LOCAL_SIGNATURE, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES,
    MAX_COMPRESSION_RATIO, MAX_ENTRY_BYTES, MAX_RETAINED_ITEMS, MAX_TOTAL_BYTES, METHOD_DEFLATED, METHOD_STORED, RATIO_FLOOR_BYTES,
    ZIP64_EOCD_SIGNATURE,
};
use vuln_match::model::{FeedLimits, FeedSettings};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};


const OPEN: &str = "CC0-1.0";


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


const TWO_ENTRIES_U64: u64 = 2;


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
        prefix_licences: BTreeMap::from([(String::new(), OPEN.to_string())]),
        allowed_licences: vec![OPEN.to_string()],
    }
}


fn open_settings() -> FeedSettings {
    settings_for(&[])
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
    settings.prefix_licences.insert("GHSA-".into(), "CC-BY-4.0".into());
    settings.allowed_licences.push("CC-BY-4.0".into());
    let report = load_feed_reader(bytes.as_slice(), &settings, &default_limits())?;
    let loaded: Vec<(&str, &str)> = report
        .records
        .iter()
        .map(|loaded| (loaded.record.id.as_str(), loaded.licence.as_str()))
        .collect();
    assert_eq!(loaded, vec![("GHSA-1", "CC-BY-4.0"), ("DSA-1", OPEN)]);
    assert_eq!(report.bad_entries, BAD_ENTRIES);
    assert_eq!(report.dropped_by_licence, 0);
    Ok(())
}


#[test]
fn licence_not_allowed_or_unknown_is_dropped() -> TestResult {
    let ghsa = record("GHSA-1");
    let dsa = record("DSA-1");
    let cgr = record("CGR-1");
    let bytes = build_zip(
        &[("a.json", ghsa.as_bytes()), ("b.json", dsa.as_bytes()), ("c.json", cgr.as_bytes())],
        CompressionMethod::Stored,
    )?;
    let mut settings = settings_for(&bytes);
    settings.prefix_licences = BTreeMap::from([("GHSA-".to_string(), "CC-BY-NC-4.0".to_string()), ("DSA-".to_string(), OPEN.to_string())]);
    let report = load_feed_reader(bytes.as_slice(), &settings, &default_limits())?;
    let ids: Vec<&str> = report.records.iter().map(|loaded| loaded.record.id.as_str()).collect();
    assert_eq!(ids, vec!["DSA-1"]);
    assert_eq!(report.dropped_by_licence, BAD_ENTRIES);
    assert_eq!(licence_of(&settings, "CGR-1"), None);
    Ok(())
}


#[test]
fn longest_prefix_wins_whatever_the_order() -> TestResult {
    let settings = FeedSettings {
        prefix_licences: BTreeMap::from([
            ("PYSEC".to_string(), "CC-BY-4.0".to_string()),
            ("PYSEC-NC".to_string(), "CC-BY-NC-4.0".to_string()),
        ]),
        ..FeedSettings::default()
    };
    assert_eq!(licence_of(&settings, "PYSEC-NC-1").as_deref(), Some("CC-BY-NC-4.0"));
    assert_eq!(licence_of(&settings, "PYSEC-1").as_deref(), Some("CC-BY-4.0"));
    Ok(())
}


#[test]
fn empty_allowed_list_refuses_the_settings() -> TestResult {
    let bytes = build_zip(&[("a.json", record("A").as_bytes())], CompressionMethod::Stored)?;
    let mut settings = settings_for(&bytes);
    settings.allowed_licences.clear();
    let result = load_feed_reader(bytes.as_slice(), &settings, &default_limits());
    assert!(matches!(result, Err(FeedError::NoAllowedLicences)));
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
        Err(FeedError::TooManyEntries {
            count: TWO_ENTRIES_U64,
            max: 1
        })
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
        "line\nbreak.json",
        "esc\u{1b}[31m.json",
        "c1\u{85}.json",
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
    assert_eq!(limits.max_retained_items, MAX_RETAINED_ITEMS);
    assert!(limits.max_total_bytes <= TOTAL_CEILING);
    Ok(())
}


const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];


const CENTRAL_METHOD_OFFSET: usize = 10;


const CENTRAL_COMPRESSED_OFFSET: usize = 20;


const LOCAL_COMPRESSED_OFFSET: usize = 18;


const EOCD_BYTES: usize = 22;


const EOCD_COUNT_AT: usize = 8;


const EOCD_SIZE_AT: usize = 12;


const EOCD_OFFSET_AT: usize = 16;


const LYING_SIZE: u32 = 0x7fff_ffff;


const UNKNOWN_METHOD: u16 = 99;


const ZIP_VERSION: u16 = 20;


const TOTAL_CEILING: u64 = 536_870_912;


const NO_EXTRA: usize = 0;


const SHORT_EXTRA: usize = 5;


const THREE_ENTRIES: usize = 3;


const THREE_ENTRIES_U64: u64 = 3;


const DIRECTORY_BODY: usize = 3;


const DESCRIPTOR_32: usize = 12;


const DESCRIPTOR_64: usize = 20;


const PADDING_BYTES: usize = 100_000;


const HEADER_CUT: usize = 14;


const NAME_CUT: usize = 33;


const GARBAGE: [u8; MAGIC_BYTES] = [CORRUPT_BYTE; MAGIC_BYTES];


fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}


fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}


fn patch(bytes: &mut [u8], at: usize, value: &[u8]) -> TestResult {
    bytes.get_mut(at..at + value.len()).ok_or("patch out of range")?.copy_from_slice(value);
    Ok(())
}


fn central_start(bytes: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(bytes
        .windows(CENTRAL_SIGNATURE.len())
        .position(|window| window == CENTRAL_SIGNATURE)
        .ok_or("no central entry")?)
}


fn local(name: &[u8], extra: usize, flags: u16, method: u16, compressed: u32, body: &[u8]) -> Vec<u8> {
    let mut out = LOCAL_SIGNATURE.to_vec();
    put16(&mut out, ZIP_VERSION);
    put16(&mut out, flags);
    put16(&mut out, method);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put32(&mut out, 0);
    put32(&mut out, compressed);
    put32(&mut out, 0);
    put16(&mut out, name.len() as u16);
    put16(&mut out, extra as u16);
    out.extend_from_slice(name);
    out.extend(std::iter::repeat_n(u8::MIN, extra));
    out.extend_from_slice(body);
    out
}


fn stored(name: &str, content: &str) -> Vec<u8> {
    local(name.as_bytes(), NO_EXTRA, 0, METHOD_STORED, content.len() as u32, content.as_bytes())
}


fn deflated(content: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    Ok(encoder.finish()?)
}


fn deflated_entry(name: &str, content: &[u8], padding: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = [deflated(content)?, vec![u8::MIN; padding]].concat();
    Ok(local(name.as_bytes(), NO_EXTRA, 0, METHOD_DEFLATED, data.len() as u32, &data))
}


fn described_entry(name: &str, content: &[u8], descriptor: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = [deflated(content)?, descriptor.to_vec()].concat();
    Ok(local(name.as_bytes(), NO_EXTRA, DESCRIPTOR_FLAG, METHOD_DEFLATED, 0, &data))
}


fn sequential(parts: &[Vec<u8>], terminator: [u8; MAGIC_BYTES]) -> Vec<u8> {
    [parts.concat(), terminator.to_vec()].concat()
}


#[test]
fn archive_ends_at_the_first_directory_record() -> TestResult {
    [CENTRAL_SIGNATURE, EOCD_SIGNATURE, ZIP64_EOCD_SIGNATURE]
        .iter()
        .try_for_each(|terminator| -> TestResult {
            let bytes = sequential(&[stored("a.json", &record("A"))], *terminator);
            assert_eq!(load(&bytes, &default_limits())?.records.len(), 1);
            let empty = sequential(&[], *terminator);
            assert!(load(&empty, &default_limits())?.records.is_empty());
            let trailing = [bytes, GARBAGE.to_vec()].concat();
            assert_eq!(load(&trailing, &default_limits())?.records.len(), 1);
            Ok(())
        })
}


#[test]
fn only_local_headers_are_used_when_the_central_directory_disagrees() -> TestResult {
    let mut bytes = build_zip(&[("a.json", record("A").as_bytes())], CompressionMethod::Stored)?;
    let at = central_start(&bytes)?;
    patch(&mut bytes, at + CENTRAL_COMPRESSED_OFFSET, &LYING_SIZE.to_le_bytes())?;
    patch(&mut bytes, at + CENTRAL_METHOD_OFFSET, &UNKNOWN_METHOD.to_le_bytes())?;
    let eocd = bytes.len() - EOCD_BYTES;
    patch(&mut bytes, eocd + EOCD_COUNT_AT, &[u8::MAX; MAGIC_BYTES])?;
    patch(&mut bytes, eocd + EOCD_SIZE_AT, &[u8::MAX; MAGIC_BYTES])?;
    patch(&mut bytes, eocd + EOCD_OFFSET_AT, &[u8::MAX; MAGIC_BYTES])?;
    assert_eq!(load(&bytes, &default_limits())?.records.len(), 1);
    Ok(())
}


#[test]
fn truncated_archives_are_refused() -> TestResult {
    let no_end = [stored("a.json", &record("A"))].concat();
    assert!(matches!(load(&no_end, &default_limits()), Err(FeedError::Truncated)));
    let with_extra = local(b"a.json", SHORT_EXTRA, 0, METHOD_STORED, 0, b"");
    let whole = stored("a.json", &record("A"));
    let cuts = [
        whole.get(..MAGIC_BYTES - 1).ok_or("short")?,
        whole.get(..HEADER_CUT).ok_or("short")?,
        whole.get(..NAME_CUT).ok_or("short")?,
        whole.get(..whole.len() - 1).ok_or("short")?,
        with_extra.get(..with_extra.len() - 1).ok_or("short")?,
    ];
    cuts.iter().try_for_each(|cut| -> TestResult {
        let outcome = load(cut, &default_limits());
        assert!(matches!(outcome, Err(FeedError::Truncated)), "{outcome:?}");
        Ok(())
    })?;
    assert!(matches!(parse_local(b"short"), Err(FeedError::Truncated)));
    let mut input: &[u8] = b"abc";
    assert!(matches!(take_bytes(&mut input, MAGIC_BYTES), Err(FeedError::Truncated)));
    assert_eq!(take_bytes(&mut input, 1)?, b"a");
    assert_eq!(input, b"bc");
    Ok(())
}


#[test]
fn unexpected_record_is_refused() -> TestResult {
    let first = sequential(&[], GARBAGE);
    assert!(matches!(load(&first, &default_limits()), Err(FeedError::BadHeader)));
    let later = sequential(&[stored("a.json", &record("A"))], GARBAGE);
    assert!(matches!(load(&later, &default_limits()), Err(FeedError::BadHeader)));
    Ok(())
}


#[test]
fn entries_are_counted_while_reading() -> TestResult {
    let three = sequential(
        &[
            stored("a.json", &record("A")),
            stored("b.json", &record("B")),
            stored("c.json", &record("C")),
        ],
        CENTRAL_SIGNATURE,
    );
    let capped = FeedLimits {
        max_entries: THREE_ENTRIES - 1,
        ..default_limits()
    };
    let outcome = load(&three, &capped);
    assert!(
        matches!(
            outcome,
            Err(FeedError::TooManyEntries {
                count: THREE_ENTRIES_U64,
                ..
            })
        ),
        "{outcome:?}"
    );
    let exact = FeedLimits {
        max_entries: THREE_ENTRIES,
        ..default_limits()
    };
    assert_eq!(load(&three, &exact)?.records.len(), THREE_ENTRIES);
    let none = FeedLimits {
        max_entries: 0,
        ..default_limits()
    };
    assert!(load(&sequential(&[], CENTRAL_SIGNATURE), &none)?.records.is_empty());
    let directories = sequential(&[stored("a/", ""), stored("b/", "")], CENTRAL_SIGNATURE);
    let one = FeedLimits {
        max_entries: 1,
        ..default_limits()
    };
    assert!(matches!(load(&directories, &one), Err(FeedError::TooManyEntries { .. })));
    Ok(())
}


#[test]
fn directory_entries_are_skipped_whatever_their_body() -> TestResult {
    let body = "x".repeat(DIRECTORY_BODY);
    let bytes = sequential(&[stored("d/", &body), stored("a.json", &record("A"))], CENTRAL_SIGNATURE);
    assert_eq!(load(&bytes, &default_limits())?.records.len(), 1);
    Ok(())
}


#[test]
fn local_sizes_are_not_trusted() -> TestResult {
    let lying_stored = local(b"a.json", NO_EXTRA, 0, METHOD_STORED, LYING_SIZE, b"{}");
    assert!(matches!(
        load(&sequential(&[lying_stored], CENTRAL_SIGNATURE), &default_limits()),
        Err(FeedError::Truncated)
    ));
    let lying_deflate = local(b"a.json", NO_EXTRA, 0, METHOD_DEFLATED, LYING_SIZE, b"{}");
    assert!(matches!(
        load(&sequential(&[lying_deflate], CENTRAL_SIGNATURE), &default_limits()),
        Err(FeedError::Truncated)
    ));
    let padded = format!(r#"{{"id":"A","aliases":[{}]}}"#, vec![r#""abcdef""#; RECORD_BYTES].join(","));
    let mut short = build_zip(&[("a.json", padded.as_bytes())], CompressionMethod::Deflated)?;
    patch(&mut short, LOCAL_COMPRESSED_OFFSET, &1u32.to_le_bytes())?;
    let outcome = load(&short, &default_limits());
    assert!(matches!(outcome, Err(FeedError::Io(_))), "{outcome:?}");
    let zeros = vec![b' '; ZERO_BYTES];
    let hidden = sequential(&[deflated_entry("a.json", &zeros, PADDING_BYTES)?], CENTRAL_SIGNATURE);
    let limits = FeedLimits {
        ratio_floor_bytes: SMALL_FLOOR,
        max_ratio: SMALL_RATIO,
        ..default_limits()
    };
    let ratio = load(&hidden, &limits);
    assert!(matches!(ratio, Err(FeedError::RatioExceeded { .. })), "{ratio:?}");
    Ok(())
}


#[test]
fn entry_size_is_bounded_while_inflating_and_while_copying() -> TestResult {
    let zeros = vec![b' '; ZERO_BYTES];
    let limits = FeedLimits {
        max_entry_bytes: SMALL_ENTRY,
        ..default_limits()
    };
    let inflated = sequential(&[deflated_entry("a.json", &zeros, 0)?], CENTRAL_SIGNATURE);
    assert!(matches!(load(&inflated, &limits), Err(FeedError::EntryTooLarge { .. })));
    let copied = sequential(&[stored("a.json", &record("A-long-identifier"))], CENTRAL_SIGNATURE);
    assert!(matches!(load(&copied, &limits), Err(FeedError::EntryTooLarge { .. })));
    Ok(())
}


#[test]
fn data_descriptors_are_skipped_in_every_form() -> TestResult {
    let signed_32 = [DESCRIPTOR_SIGNATURE.to_vec(), vec![u8::MIN; DESCRIPTOR_32]].concat();
    let unsigned_32 = vec![u8::MIN; DESCRIPTOR_32];
    let signed_64 = [DESCRIPTOR_SIGNATURE.to_vec(), vec![u8::MIN; DESCRIPTOR_64]].concat();
    let unsigned_64 = vec![u8::MIN; DESCRIPTOR_64];
    [signed_32, unsigned_32, signed_64, unsigned_64]
        .iter()
        .try_for_each(|descriptor| -> TestResult {
            let first = described_entry("a.json", record("A").as_bytes(), descriptor)?;
            let second = described_entry("b.json", record("B").as_bytes(), descriptor)?;
            let bytes = sequential(&[first, second, stored("c.json", &record("C"))], CENTRAL_SIGNATURE);
            let ids: Vec<String> = load(&bytes, &default_limits())?
                .records
                .into_iter()
                .map(|loaded| loaded.record.id)
                .collect();
            assert_eq!(ids, vec!["A", "B", "C"]);
            Ok(())
        })
}


#[test]
fn data_descriptor_entries_share_the_running_bounds() -> TestResult {
    let zeros = vec![b' '; ZERO_BYTES];
    let descriptor = vec![u8::MIN; DESCRIPTOR_32];
    let ratio = FeedLimits {
        ratio_floor_bytes: SMALL_FLOOR,
        max_ratio: SMALL_RATIO,
        ..default_limits()
    };
    let bomb = sequential(&[described_entry("a.json", &zeros, &descriptor)?], CENTRAL_SIGNATURE);
    assert!(matches!(load(&bomb, &ratio), Err(FeedError::RatioExceeded { .. })));
    let entry = FeedLimits {
        max_entry_bytes: SMALL_ENTRY,
        ..default_limits()
    };
    let outcome = load(&bomb, &entry);
    assert!(matches!(outcome, Err(FeedError::EntryTooLarge { .. })), "{outcome:?}");
    let content = record("A");
    let two = sequential(
        &[
            described_entry("a.json", content.as_bytes(), &descriptor)?,
            described_entry("b.json", content.as_bytes(), &descriptor)?,
        ],
        CENTRAL_SIGNATURE,
    );
    let total = FeedLimits {
        max_total_bytes: content.len() as u64,
        ..default_limits()
    };
    assert!(matches!(load(&two, &total), Err(FeedError::TotalTooLarge { .. })));
    let entries = FeedLimits {
        max_entries: 1,
        ..default_limits()
    };
    assert!(matches!(load(&two, &entries), Err(FeedError::TooManyEntries { .. })));
    Ok(())
}


#[test]
fn malformed_descriptors_are_refused() -> TestResult {
    let garbage = described_entry("a.json", record("A").as_bytes(), &[1; DESCRIPTOR_32 + 1])?;
    let outcome = load(&sequential(&[garbage], CENTRAL_SIGNATURE), &default_limits());
    assert!(matches!(outcome, Err(FeedError::BadDescriptor)), "{outcome:?}");
    let cut = described_entry("a.json", record("A").as_bytes(), &[])?;
    assert!(matches!(load(&cut, &default_limits()), Err(FeedError::BadDescriptor)));
    Ok(())
}


#[test]
fn unsupported_entries_are_refused() -> TestResult {
    let stored_with_descriptor = local(b"a.json", NO_EXTRA, DESCRIPTOR_FLAG, METHOD_STORED, 0, b"");
    let unknown = local(b"a.json", NO_EXTRA, 0, UNKNOWN_METHOD, 0, b"");
    let encrypted = local(b"a.json", NO_EXTRA, ENCRYPTED_FLAG, METHOD_STORED, 0, b"");
    [stored_with_descriptor, unknown, encrypted].iter().try_for_each(|entry| -> TestResult {
        let outcome = load(&sequential(std::slice::from_ref(entry), CENTRAL_SIGNATURE), &default_limits());
        assert!(matches!(outcome, Err(FeedError::UnsupportedMethod { .. })), "{outcome:?}");
        Ok(())
    })
}


#[test]
fn read_and_format_failures_are_reported() -> TestResult {
    assert!(matches!(
        load_feed_reader(Failing, &open_settings(), &default_limits()),
        Err(FeedError::Io(_))
    ));
    assert!(matches!(
        load_feed(Path::new("/nonexistent/all.zip"), &open_settings(), &default_limits()),
        Err(FeedError::Io(_))
    ));
    assert!(matches!(load(b"not a zip", &default_limits()), Err(FeedError::BadHeader)));
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
fn retained_elements_are_capped() -> TestResult {
    let content = r#"{"id":"A","affected":[{"package":{"ecosystem":"Debian","name":"p"},"versions":["1","2"],
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3"}]}]}]}"#;
    let bytes = build_zip(
        &[("a.json", content.as_bytes()), ("b.json", content.as_bytes())],
        CompressionMethod::Stored,
    )?;
    let report = load(
        &bytes,
        &FeedLimits {
            max_retained_items: RETAINED_PAIR,
            ..default_limits()
        },
    )?;
    assert_eq!(report.retained_items, RETAINED_PAIR);
    assert_eq!(retained_items(&report.records.first().ok_or("no record")?.record), RETAINED_ONE);
    let outcome = load(
        &bytes,
        &FeedLimits {
            max_retained_items: RETAINED_ONE,
            ..default_limits()
        },
    );
    assert!(matches!(outcome, Err(FeedError::TooManyRetained { .. })), "{outcome:?}");
    Ok(())
}


const RETAINED_ONE: u64 = 6;


const RETAINED_PAIR: u64 = 12;


#[test]
fn aliases_and_empty_entries_count_as_retained() -> TestResult {
    let aliases = r#"{"id":"A","aliases":["a","b","c"]}"#;
    let empty = r#"{"id":"B","affected":[{"package":{"ecosystem":"Debian","name":"p"},"ranges":[{"type":"ECOSYSTEM"},{"type":"GIT"}]}]}"#;
    let bytes = build_zip(&[("a.json", aliases.as_bytes()), ("b.json", empty.as_bytes())], CompressionMethod::Stored)?;
    let report = load(
        &bytes,
        &FeedLimits {
            max_retained_items: ALIAS_ITEMS + EMPTY_ITEMS,
            ..default_limits()
        },
    )?;
    assert_eq!(report.retained_items, ALIAS_ITEMS + EMPTY_ITEMS);
    let outcome = load(
        &bytes,
        &FeedLimits {
            max_retained_items: ALIAS_ITEMS + EMPTY_ITEMS - 1,
            ..default_limits()
        },
    );
    assert!(matches!(outcome, Err(FeedError::TooManyRetained { .. })), "{outcome:?}");
    let only_aliases = build_zip(&[("a.json", aliases.as_bytes())], CompressionMethod::Stored)?;
    let aliased = load(
        &only_aliases,
        &FeedLimits {
            max_retained_items: ALIAS_ITEMS - 1,
            ..default_limits()
        },
    );
    assert!(matches!(aliased, Err(FeedError::TooManyRetained { .. })), "{aliased:?}");
    Ok(())
}


const ALIAS_ITEMS: u64 = 3;


const EMPTY_ITEMS: u64 = 3;
