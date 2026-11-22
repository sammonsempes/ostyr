use crate::model::{WireScan, BITS_PER_BYTE, GRPC_PREFIX_BYTES};
use crate::types::WireLengths;
use axum::body::Body;
use futures_util::StreamExt;
use std::collections::VecDeque;
use std::sync::{Arc, PoisonError};


pub fn new_wire_lengths() -> WireLengths {
    Arc::new(std::sync::Mutex::new(VecDeque::new()))
}


/// Takes the oldest wire length not yet paired with a decoded frame; `usize::MAX` when none is left, which never equals a real length.
pub fn pop_wire_length(lengths: &WireLengths) -> usize {
    lengths.lock().unwrap_or_else(PoisonError::into_inner).pop_front().unwrap_or(usize::MAX)
}


pub fn push_wire_length(lengths: &WireLengths, length: u32) {
    lengths
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push_back(usize::try_from(length).unwrap_or(usize::MAX));
}


/// Advances the prefix reader by one byte; a completed prefix records the message length it announced.
pub fn scan_byte(scan: WireScan, byte: u8, lengths: &WireLengths) -> WireScan {
    if scan.remaining > 0 {
        WireScan {
            remaining: scan.remaining - 1,
            ..scan
        }
    } else if scan.prefix_seen == 0 {
        WireScan {
            prefix_seen: 1,
            length: 0,
            remaining: 0,
        }
    } else {
        let length = (scan.length << BITS_PER_BYTE) | u32::from(byte);
        let seen = scan.prefix_seen + 1;
        if seen == GRPC_PREFIX_BYTES {
            push_wire_length(lengths, length);
            WireScan {
                prefix_seen: 0,
                length: 0,
                remaining: length,
            }
        } else {
            WireScan {
                prefix_seen: seen,
                length,
                remaining: 0,
            }
        }
    }
}


pub fn scan_chunk(scan: WireScan, chunk: &[u8], lengths: &WireLengths) -> WireScan {
    chunk.iter().fold(scan, |state, byte| scan_byte(state, *byte, lengths))
}


/// The request body unchanged, with the wire length of every gRPC message recorded as it passes, before tonic decodes it.
pub fn scanned_body(body: Body, lengths: WireLengths) -> Body {
    let stream = body.into_data_stream().scan(WireScan::default(), move |scan, chunk| {
        if let Ok(bytes) = &chunk {
            *scan = scan_chunk(*scan, bytes, &lengths);
        }
        std::future::ready(Some(chunk))
    });
    Body::from_stream(stream)
}
