use ebpf_probes::record::{decode_exec, escape_comm, DecodeError, ExecRecord, COMM_BYTES, EXEC_RECORD_BYTES};
use std::collections::HashSet;
use std::error::Error;


const PID: u32 = 4242;


const PPID: u32 = 1;


const UID: u32 = 1000;


const GID: u32 = 1001;


const MONOTONIC_NS: u64 = 0x0102_0304_0506_0708;


const ESCAPE: u8 = 0x1b;


const CARRIAGE_RETURN: u8 = b'\r';


const NEWLINE: u8 = b'\n';


const HIGH_BYTE: u8 = 0xff;


const OFFSET_COMM: usize = 24;


const SHORT_BY_ONE: usize = 1;


const EXTRA_BYTES: usize = 1;


fn record_bytes(comm: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    [PID, PPID, UID, GID].iter().for_each(|word| bytes.extend_from_slice(&word.to_le_bytes()));
    bytes.extend_from_slice(&MONOTONIC_NS.to_le_bytes());
    let mut field = comm.to_vec();
    field.resize(COMM_BYTES, 0);
    bytes.extend_from_slice(&field);
    bytes
}


#[test]
fn layout_constants_match_the_documented_record() -> Result<(), Box<dyn Error>> {
    assert_eq!(EXEC_RECORD_BYTES, OFFSET_COMM + COMM_BYTES);
    assert_eq!(record_bytes(b"x").len(), EXEC_RECORD_BYTES);
    Ok(())
}


#[test]
fn decodes_every_field_little_endian() -> Result<(), DecodeError> {
    let record = decode_exec(&record_bytes(b"bash"))?;
    let expected = ExecRecord {
        pid: PID,
        ppid: PPID,
        uid: UID,
        gid: GID,
        monotonic_ns: MONOTONIC_NS,
        comm: "bash".to_string(),
    };
    assert_eq!(record, expected);
    Ok(())
}


#[test]
fn comm_is_cut_at_the_first_nul() -> Result<(), DecodeError> {
    let record = decode_exec(&record_bytes(b"ab\0cd"))?;
    assert_eq!(record.comm, "ab");
    Ok(())
}


#[test]
fn comm_without_nul_keeps_sixteen_bytes() -> Result<(), DecodeError> {
    let record = decode_exec(&record_bytes(&[b'a'; COMM_BYTES]))?;
    assert_eq!(record.comm.len(), COMM_BYTES);
    Ok(())
}


#[test]
fn comm_with_control_bytes_is_escaped_never_raw() -> Result<(), DecodeError> {
    let record = decode_exec(&record_bytes(&[b'a', ESCAPE, b'[', CARRIAGE_RETURN, NEWLINE, HIGH_BYTE, b' ', b'z']))?;
    assert_eq!(record.comm, "a\\x1b[\\x0d\\x0a\\xff z");
    assert!(record.comm.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' '));
    Ok(())
}


#[test]
fn escape_comm_stops_at_nul_and_escapes() -> Result<(), Box<dyn Error>> {
    assert_eq!(escape_comm(&[ESCAPE, 0, b'x']), "\\x1b");
    Ok(())
}


#[test]
fn comm_of_sixteen_escapes_stays_bounded_and_printable() -> Result<(), DecodeError> {
    let record = decode_exec(&record_bytes(&[ESCAPE; COMM_BYTES]))?;
    assert_eq!(record.comm, "\\x1b".repeat(COMM_BYTES));
    Ok(())
}


#[test]
fn wrong_sizes_name_only_the_length() -> Result<(), Box<dyn Error>> {
    let good = record_bytes(b"bash");
    let empty: &[u8] = &[];
    let short = good.get(..EXEC_RECORD_BYTES - SHORT_BY_ONE).unwrap_or(empty);
    let mut long = good.clone();
    long.extend_from_slice(&[ESCAPE; EXTRA_BYTES]);
    assert_eq!(decode_exec(empty), Err(DecodeError::WrongSize { got: 0 }));
    assert_eq!(
        decode_exec(short),
        Err(DecodeError::WrongSize {
            got: EXEC_RECORD_BYTES - SHORT_BY_ONE
        })
    );
    assert_eq!(
        decode_exec(&long),
        Err(DecodeError::WrongSize {
            got: EXEC_RECORD_BYTES + EXTRA_BYTES
        })
    );
    assert_eq!(DecodeError::WrongSize { got: 0 }.to_string(), "exec record has 0 bytes, expected 40");
    Ok(())
}


#[test]
fn every_prefix_shorter_than_a_record_is_refused() -> Result<(), Box<dyn Error>> {
    let good = record_bytes(b"bash");
    let refused = (0..EXEC_RECORD_BYTES).all(|length| good.get(..length).is_some_and(|prefix| decode_exec(prefix).is_err()));
    assert!(refused);
    Ok(())
}


#[test]
fn a_backslash_is_escaped_so_text_never_reads_like_an_escape() -> Result<(), Box<dyn Error>> {
    assert_eq!(escape_comm(b"\\x1b[31m"), "\\x5cx1b[31m");
    assert_ne!(escape_comm(b"\\x1b"), escape_comm(&[ESCAPE]));
    Ok(())
}


#[test]
fn two_different_raw_comms_never_decode_alike() -> Result<(), Box<dyn Error>> {
    let alphabet = [b'\\', b'x', b'1', b'b', ESCAPE, b'0', b'5', b'c'];
    let singles = (1..=u8::MAX).map(|byte| vec![byte]);
    let pairs = alphabet.iter().flat_map(|first| alphabet.iter().map(move |second| vec![*first, *second]));
    let extras = [b"\\x1b".to_vec(), b"\\\\x5c".to_vec(), b"\\x5c".to_vec()];
    let samples: HashSet<Vec<u8>> = singles.chain(pairs).chain(extras).collect();
    let decoded: HashSet<String> = samples.iter().map(|raw| escape_comm(raw)).collect();
    assert_eq!(decoded.len(), samples.len());
    Ok(())
}
