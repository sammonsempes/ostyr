use crate::limits::Limits;


const HEADER_NAME_END: u8 = b':';


const PART_PREFIX: &[u8] = b"--";


const TYPE_PREFIX: &[u8] = b"content-type:";


const MESSAGE_TYPE: &[u8] = b"message/";


const NESTED_FACTOR: usize = 2;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan<'a> {
    pub usable: &'a [u8],
    pub cut: bool,
}


#[derive(Debug, Clone, Copy)]
struct Seen {
    offset: usize,
    header_lines: usize,
    part_lines: usize,
    message_lines: usize,
}


fn is_header_line(line: &[u8]) -> bool {
    line.iter()
        .position(|byte| *byte == HEADER_NAME_END)
        .and_then(|end| line.get(..end))
        .is_some_and(|name| !name.is_empty() && name.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-'))
}


fn has_message_type(line: &[u8]) -> bool {
    line.windows(MESSAGE_TYPE.len()).any(|window| window.eq_ignore_ascii_case(MESSAGE_TYPE))
}


fn is_message_type_line(line: &[u8]) -> bool {
    line.get(..TYPE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TYPE_PREFIX))
        && has_message_type(line)
}


fn is_part_line(line: &[u8]) -> bool {
    line.starts_with(PART_PREFIX) || is_message_type_line(line)
}


/// Cuts the raw message before the line that exceeds the header-line, part-line or `message/` line budget, so the parser never materialises more.
pub fn scan<'a>(raw: &'a [u8], limits: &Limits) -> Scan<'a> {
    let header_budget = limits.headers.saturating_mul(limits.parts);
    let part_budget = limits.parts.saturating_mul(NESTED_FACTOR);
    let start = Seen {
        offset: 0,
        header_lines: 0,
        part_lines: 0,
        message_lines: 0,
    };
    let outcome = raw.split_inclusive(|byte| *byte == b'\n').try_fold(start, |seen, line| {
        let next = Seen {
            offset: seen.offset.saturating_add(line.len()),
            header_lines: seen.header_lines + usize::from(is_header_line(line)),
            part_lines: seen.part_lines + usize::from(is_part_line(line)),
            message_lines: seen.message_lines + usize::from(has_message_type(line)),
        };
        if next.header_lines > header_budget || next.part_lines > part_budget || next.message_lines > limits.nested_messages {
            Err(seen.offset)
        } else {
            Ok(next)
        }
    });
    match outcome {
        Ok(_) => Scan { usable: raw, cut: false },
        Err(offset) => Scan {
            usable: raw.get(..offset).unwrap_or(raw),
            cut: true,
        },
    }
}
