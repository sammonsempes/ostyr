use ebpf_probes::record::{
    decode_exec, decode_file, exec_time, file_time, DecodeError, FileRecord, FILE_HEADER_WORDS, FILE_PATH_BYTES, FILE_RECORD_BYTES, FILE_RECORD_KIND,
    STATUS_PATH_ERROR, STATUS_TOO_LONG, STATUS_UNLINKED,
};
use std::error::Error;


const PID: u32 = 4242;


const UID: u32 = 1000;


const OPEN_FLAGS: u32 = 0o101;


const NS: u64 = 0x0000_0005_0000_0007;


const MODE: u32 = 0x0010_0002;


const DEVICE: u32 = 0x0010_0001;


const INODE: u64 = 0x0000_0009_0000_000b;


const MOUNT_NAMESPACE: u32 = 4_026_531_841;


const UNKNOWN_STATUS: u32 = 8;


const WRONG_KIND: u32 = 1;


const WORD: usize = 4;


const EXEC_BYTES: usize = 40;


const EXPECTED_BYTES: usize = 304;


const SHORT_GOT: usize = 3;


fn raw(kind: u32, status: u32, path: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    [kind, PID, UID, OPEN_FLAGS, MODE, status]
        .iter()
        .for_each(|word| bytes.extend_from_slice(&word.to_le_bytes()));
    bytes.extend_from_slice(&NS.to_le_bytes());
    bytes.extend_from_slice(&DEVICE.to_le_bytes());
    bytes.extend_from_slice(&INODE.to_le_bytes());
    bytes.extend_from_slice(&MOUNT_NAMESPACE.to_le_bytes());
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
            mode: MODE,
            too_long: false,
            path_error: false,
            unlinked: false,
            monotonic_ns: NS,
            device: DEVICE,
            inode: INODE,
            mount_namespace: MOUNT_NAMESPACE,
            path: "/etc/passwd".to_string(),
        }
    );
    assert_eq!(file_time(&record), NS);
    assert_eq!(exec_time(&decode_exec(&[0u8; EXEC_BYTES])?), 0);
    Ok(())
}


#[test]
fn the_status_bits_are_the_too_long_path_error_and_unlinked_flags() -> Result<(), Box<dyn Error>> {
    let long = decoded(FILE_RECORD_KIND, STATUS_TOO_LONG, b"")?;
    assert_eq!((long.too_long, long.path_error, long.unlinked), (true, false, false));
    let failed = decoded(FILE_RECORD_KIND, STATUS_PATH_ERROR, b"")?;
    assert_eq!((failed.too_long, failed.path_error, failed.unlinked), (false, true, false));
    let gone = decoded(FILE_RECORD_KIND, STATUS_UNLINKED, b"/t/x (deleted)")?;
    assert_eq!(
        (gone.too_long, gone.path_error, gone.unlinked, gone.path.as_str()),
        (false, false, true, "/t/x (deleted)")
    );
    let all = decoded(FILE_RECORD_KIND, STATUS_TOO_LONG | STATUS_PATH_ERROR | STATUS_UNLINKED, b"")?;
    assert_eq!((all.too_long, all.path_error, all.unlinked), (true, true, true));
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
            "file record has 3 bytes, expected 304".to_string(),
            "file record has kind 1, expected 3".to_string(),
            "file record has unknown status bits 8".to_string(),
        ]
    );
    Ok(())
}


#[test]
fn the_path_is_cut_at_its_first_nul_so_stale_bytes_after_it_never_show() -> Result<(), Box<dyn Error>> {
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"ab\0cd")?.path, "ab");
    assert_eq!(decoded(FILE_RECORD_KIND, 0, b"\0\0x")?.path, "");
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
    let record = decoded(FILE_RECORD_KIND, STATUS_TOO_LONG, &full)?;
    assert_eq!(record.path.len(), FILE_PATH_BYTES);
    assert!(record.too_long);
    Ok(())
}
