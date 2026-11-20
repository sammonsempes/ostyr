use crate::cursor::is_time_text;
use crate::model::{SystemInfo, MAX_EVENT_ID_DIGITS, MAX_ID_DIGITS, MAX_RECORD_ID, MAX_SYSTEM_BYTES};


const SYSTEM_OPEN: &[u8] = b"<System>";


const SYSTEM_CLOSE: &[u8] = b"</System>";


const TIME_TAG: &[u8] = b"<TimeCreated";


const TIME_KEY: &[u8] = b"SystemTime=";


const RADIX: u64 = 10;


pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}


pub fn system_region(head: &[u8]) -> &[u8] {
    let after = find(head, SYSTEM_OPEN).and_then(|at| head.get(at + SYSTEM_OPEN.len()..)).unwrap_or(&[]);
    find(after, SYSTEM_CLOSE).and_then(|end| after.get(..end)).unwrap_or(after)
}


pub fn element_text<'a>(region: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let rest = find(region, name).and_then(|at| region.get(at + name.len()..));
    let content = rest.and_then(|tail| match tail.first() {
        Some(b'>') => tail.get(1..),
        Some(b' ') => tail.iter().position(|byte| *byte == b'>').and_then(|close| tail.get(close + 1..)),
        _ => None,
    });
    content.and_then(|body| body.iter().position(|byte| *byte == b'<').and_then(|end| body.get(..end)))
}


pub fn digits(text: &[u8], max_digits: usize) -> Option<u64> {
    let sized = !text.is_empty() && text.len() <= max_digits;
    sized
        .then(|| {
            text.iter().try_fold(0u64, |total, byte| {
                byte.is_ascii_digit()
                    .then(|| total.checked_mul(RADIX))
                    .flatten()
                    .and_then(|shifted| shifted.checked_add(u64::from(byte - b'0')))
            })
        })
        .flatten()
}


pub fn system_time(region: &[u8]) -> Option<String> {
    let tag = find(region, TIME_TAG)
        .and_then(|at| region.get(at..))
        .and_then(|tail| tail.iter().position(|byte| *byte == b'>').and_then(|end| tail.get(..end)));
    let value = tag.and_then(|inner| find(inner, TIME_KEY).and_then(|at| inner.get(at + TIME_KEY.len()..)));
    let text = value.and_then(|rest| match rest.first() {
        Some(quote @ (b'\'' | b'"')) => rest
            .get(1..)
            .and_then(|body| body.iter().position(|byte| byte == quote).and_then(|end| body.get(..end))),
        _ => None,
    });
    text.and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|found| is_time_text(found))
        .map(str::to_string)
}


pub fn scan_system(item: &[u8]) -> SystemInfo {
    let head = item.get(..MAX_SYSTEM_BYTES).unwrap_or(item);
    let region = system_region(head);
    SystemInfo {
        record_id: element_text(region, b"<EventRecordID")
            .and_then(|text| digits(text, MAX_ID_DIGITS))
            .filter(|id| *id > 0 && *id <= MAX_RECORD_ID),
        event_id: element_text(region, b"<EventID")
            .and_then(|text| digits(text, MAX_EVENT_ID_DIGITS))
            .and_then(|id| u32::try_from(id).ok()),
        time: system_time(region),
    }
}
