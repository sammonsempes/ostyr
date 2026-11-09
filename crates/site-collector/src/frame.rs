use crate::error::SpoolError;
use crate::spool_model::{FrameRead, Priority, Record, FRAME_HEADER_BYTES, MAX_PAYLOAD_BYTES};
use std::io::Read;


const LEN_BYTES: usize = 4;


const PRIORITY_BYTES: usize = 1;


const SEQUENCE_BYTES: usize = 8;


const CRC_BYTES: usize = 4;


const PRIORITY_LOW: u8 = 0;


const PRIORITY_HIGH: u8 = 1;


pub fn priority_byte(priority: Priority) -> u8 {
    match priority {
        Priority::Low => PRIORITY_LOW,
        Priority::High => PRIORITY_HIGH,
    }
}


pub fn priority_from_byte(byte: u8) -> Option<Priority> {
    match byte {
        PRIORITY_LOW => Some(Priority::Low),
        PRIORITY_HIGH => Some(Priority::High),
        _ => None,
    }
}


pub fn frame_crc(priority: u8, sequence: u64, payload: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[priority]);
    hasher.update(&sequence.to_le_bytes());
    hasher.update(payload);
    hasher.finalize()
}


pub fn frame_len(payload_len: usize) -> u64 {
    (FRAME_HEADER_BYTES + payload_len) as u64
}


pub fn encode_frame(record: &Record) -> Result<Vec<u8>, SpoolError> {
    (record.payload.len() <= MAX_PAYLOAD_BYTES)
        .then_some(())
        .ok_or(SpoolError::PayloadTooLarge)?;
    let priority = priority_byte(record.priority);
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + record.payload.len());
    frame.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    frame.push(priority);
    frame.extend_from_slice(&record.sequence.to_le_bytes());
    frame.extend_from_slice(&frame_crc(priority, record.sequence, &record.payload).to_le_bytes());
    frame.extend_from_slice(&record.payload);
    Ok(frame)
}


pub fn read_frame<Source: Read>(reader: &mut Source, remaining: u64) -> Result<FrameRead, SpoolError> {
    let outcome = if remaining == 0 {
        FrameRead::End
    } else if remaining < FRAME_HEADER_BYTES as u64 {
        FrameRead::Torn
    } else {
        read_frame_body(reader, remaining)?
    };
    Ok(outcome)
}


fn read_frame_body<Source: Read>(reader: &mut Source, remaining: u64) -> Result<FrameRead, SpoolError> {
    let mut len_bytes: [u8; LEN_BYTES] = [0; LEN_BYTES];
    let mut priority_bytes: [u8; PRIORITY_BYTES] = [0; PRIORITY_BYTES];
    let mut sequence_bytes: [u8; SEQUENCE_BYTES] = [0; SEQUENCE_BYTES];
    let mut crc_bytes: [u8; CRC_BYTES] = [0; CRC_BYTES];
    reader.read_exact(&mut len_bytes)?;
    reader.read_exact(&mut priority_bytes)?;
    reader.read_exact(&mut sequence_bytes)?;
    reader.read_exact(&mut crc_bytes)?;
    let payload_len = u64::from(u32::from_le_bytes(len_bytes));
    let total = FRAME_HEADER_BYTES as u64 + payload_len;
    let outcome = if payload_len > MAX_PAYLOAD_BYTES as u64 || total > remaining {
        FrameRead::Torn
    } else {
        let mut payload = Vec::new();
        reader.take(payload_len).read_to_end(&mut payload)?;
        let priority = u8::from_le_bytes(priority_bytes);
        let sequence = u64::from_le_bytes(sequence_bytes);
        let crc_ok = frame_crc(priority, sequence, &payload) == u32::from_le_bytes(crc_bytes);
        match priority_from_byte(priority) {
            Some(known) if crc_ok => FrameRead::Frame(
                Record {
                    priority: known,
                    sequence,
                    payload,
                },
                total,
            ),
            _ => FrameRead::Torn,
        }
    };
    Ok(outcome)
}
