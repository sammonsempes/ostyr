use ebpf_probes::record::{
    decode_exec, decode_file, exec_time, file_time, DecodeError, FileRecord, FILE_HEADER_WORDS, FILE_PATH_BYTES, FILE_RECORD_BYTES, FILE_RECORD_KIND,
    STATUS_CUT, STATUS_UNREADABLE,
};
use std::error::Error;


const PID: u32 = 4242;


const UID: u32 = 1000;


const OPEN_FLAGS: u32 = 0o101;


const NS: u64 = 0x0000_0005_0000_0007;


const UNKNOWN_STATUS: u32 = 4;


const WRONG_KIND: u32 = 1;


const WORD: usize = 4;


const EXEC_BYTES: usize = 40;


const EXPECTED_BYTES: usize = 284;


const SHORT_GOT: usize = 3;


fn raw(kind: u32, status: u32, path: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    [kind, PID, UID, OPEN_FLAGS, status]
        .iter()
        .for_each(|word| bytes.extend_from_slice(&word.to_le_bytes()));
    bytes.extend_from_slice(&NS.to_le_bytes());
    let mut field = path.to_vec();
    field.resize(FILE_PATH_BYTES, 0);
    bytes.extend_from_slice(&field);
    bytes
}


fn decoded(kind: u32, status: u32, path: &[u8]) -> Result<FileRecord, Box<dyn Error>> {
    Ok(decode_file(&raw(kind, status, path))?)
}


#[test]
fn the_layout_constants_match_the_kernel_record() -> Result<(), Box<dyn Error>> {
    assert_eq!(FILE_HEADER_WORDS * WORD + FILE_PATH_BYTES, FILE_RECORD_BYTES);
    assert_eq!(FILE_RECORD_BYTES, EXPECTED_BYTES);
    assert_eq!(raw(FILE_RECORD_KIND, 0, b"").len(), FILE_RECORD_BYTES);
    Ok(())
}


#[test]
fn a_record_decodes_every_field_at_its_offset() -> Result<(), Box<dyn Error>> {
    let record = decoded(FILE_RECORD_KIND, 0, b"/etc/passwd")?;
    assert_eq!(
        record,
        FileRecord {
            pid: PID,
            uid: UID,
            flags: OPEN_FLAGS,
            cut: false,
            unreadable: false,
            monotonic_ns: NS,
            path: "/etc/passwd".to_string(),
        }
    );
    assert_eq!(file_time(&record), NS);
    assert_eq!(exec_time(&decode_exec(&[0u8; EXEC_BYTES])?), 0);
    Ok(())
}


#[test]
fn the_status_bits_are_the_cut_and_unreadable_flags() -> Result<(), Box<dyn Error>> {
    let cut = decoded(FILE_RECORD_KIND, STATUS_CUT, b"/long")?;
    assert_eq!((cut.cut, cut.unreadable), (true, false));
    let unreadable = decoded(FILE_RECORD_KIND, STATUS_UNREADABLE, b"")?;
    assert_eq!((unreadable.cut, unreadable.unreadable, unreadable.path.as_str()), (false, true, ""));
    let both = decoded(FILE_RECORD_KIND, STATUS_CUT | STATUS_UNREADABLE, b"")?;
    assert_eq!((both.cut, both.unreadable), (true, true));
    Ok(())
}


#[test]
fn a_wrong_length_kind_or_status_is_refused_by_name() -> Result<(), Box<dyn Error>> {
    let good = raw(FILE_RECORD_KIND, 0, b"/a");
    let short = good.get(..FILE_RECORD_BYTES - 1).ok_or("short")?;
    assert_eq!(decode_file(short), Err(DecodeError::FileWrongSize { got: FILE_RECORD_BYTES - 1 }));
    let mut long = good.clone();
    long.push(0);
    assert_eq!(decode_file(&long), Err(DecodeError::FileWrongSize { got: FILE_RECORD_BYTES + 1 }));
    assert_eq!(decode_file(&[]), Err(DecodeError::FileWrongSize { got: 0 }));
    assert_eq!(decode_file(&[0u8; EXEC_BYTES]), Err(DecodeError::FileWrongSize { got: EXEC_BYTES }));
    assert_eq!(
        decode_file(&raw(WRONG_KIND, 0, b"/a")),
        Err(DecodeError::FileWrongKind { got: WRONG_KIND })
    );
    assert_eq!(decode_file(&raw(0, 0, b"/a")), Err(DecodeError::FileWrongKind { got: 0 }));
    assert_eq!(
        decode_file(&raw(FILE_RECORD_KIND, UNKNOWN_STATUS, b"/a")),
        Err(DecodeError::FileUnknownStatus { got: UNKNOWN_STATUS })
    );
    let texts = [
        DecodeError::FileWrongSize { got: SHORT_GOT }.to_string(),
        DecodeError::FileWrongKind { got: WRONG_KIND }.to_string(),
        DecodeError::FileUnknownStatus { got: UNKNOWN_STATUS }.to_string(),
    ];
    assert_eq!(
        texts,
        [
            "file record has 3 bytes, expected 284".to_string(),
            "file record has kind 1, expected 2".to_string(),
            "file record has unknown status bits 4".to_string(),
        ]
    );
    Ok(())
}


#[test]
fn a_nul_before_the_end_keeps_the_bytes_after_it_escaped() -> Result<(), Box<dyn Error>> {
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"ab\0cd")?.path, "ab\\x00cd");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"\0\0x")?.path, "\\x00\\x00x");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"")?.path, "");
    Ok(())
}


#[test]
fn invalid_utf8_controls_and_backslashes_are_escaped_unambiguously() -> Result<(), Box<dyn Error>> {
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"/t/\xff\xfe")?.path, "/t/\\xff\\xfe");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"/t/a\nb\x1b[0m")?.path, "/t/a\\x0ab\\x1b[0m");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"/t/a\\x41")?.path, "/t/a\\x5cx41");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, "/t/\u{e9}".as_bytes())?.path, "/t/\\xc3\\xa9");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"with space")?.path, "with space");
    Ok(())
}


#[test]
fn a_full_field_keeps_all_its_bytes() -> Result<(), Box<dyn Error>> {
    let full = vec![b'a'; FILE_PATH_BYTES];
    let record = decoded(FILE_RECORD_KIND, STATUS_CUT, &full)?;
    assert_eq!(record.path.len(), FILE_PATH_BYTES);
    assert!(record.cut);
    Ok(())
}
