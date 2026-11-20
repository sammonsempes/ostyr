use crate::limits::Limits;
use crate::mime::{embedded_header, header_found, header_of, is_blank, is_folded, Kind};
use std::borrow::Cow;
use std::ops::Range;


const HEADER_NAME_END: u8 = b':';


const PART_PREFIX: &[u8] = b"--";


const TYPE_PREFIX: &[u8] = b"content-type:";


const MESSAGE_TYPE: &[u8] = b"message/";


const NESTED_FACTOR: usize = 2;


const CARRIAGE_RETURN: u8 = b'\r';


const LINE_FEED: u8 = b'\n';


const BLANK: u8 = b' ';


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan<'a> {
    pub usable: Cow<'a, [u8]>,
    pub cut: bool,
    pub refused: usize,
    pub lost_bytes: usize,
    pub lost_part: Option<usize>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
struct Refusal {
    range: Range<usize>,
    part: usize,
}


#[derive(Debug, Clone)]
struct Open {
    kind: Kind,
    value: Vec<u8>,
    overflow: bool,
    embedded: bool,
}


#[derive(Debug, Clone, Default)]
struct Block {
    start: Option<usize>,
    blank_from: Option<usize>,
    active: bool,
    embedded: bool,
    suspect: bool,
    from_delimiter: bool,
    message: bool,
    digest: bool,
    encoded: bool,
    last_clear: Option<bool>,
    open: Option<Open>,
}


#[derive(Debug, Clone, Default)]
struct Seen {
    offset: usize,
    header_lines: usize,
    part_lines: usize,
    nested: usize,
    digest: bool,
    blocks: usize,
    region: bool,
    block: Block,
    refused: Vec<Refusal>,
}


#[derive(Debug, Clone)]
struct Cut {
    offset: usize,
    part: usize,
    refused: Vec<Refusal>,
}


#[derive(Debug, Clone, Copy)]
struct Budgets {
    headers: usize,
    parts: usize,
    nested: usize,
    value_bytes: usize,
}


fn is_header_line(line: &[u8]) -> bool {
    line.iter()
        .position(|byte| *byte == HEADER_NAME_END)
        .and_then(|end| line.get(..end))
        .is_some_and(|name| !name.is_empty() && name.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-'))
}


fn is_message_type_line(line: &[u8]) -> bool {
    line.get(..TYPE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TYPE_PREFIX))
        && line.windows(MESSAGE_TYPE.len()).any(|window| window.eq_ignore_ascii_case(MESSAGE_TYPE))
}


fn is_part_line(line: &[u8]) -> bool {
    line.starts_with(PART_PREFIX) || is_message_type_line(line)
}


fn append(open: Open, bytes: &[u8], cap: usize) -> Open {
    let room = cap.saturating_sub(open.value.len());
    let taken = bytes.get(..room).unwrap_or(bytes);
    let mut value = open.value;
    if open.kind != Kind::Other {
        value.extend_from_slice(taken);
    }
    Open {
        value,
        overflow: open.overflow || bytes.len() > room,
        ..open
    }
}


fn close_header(block: Block) -> Block {
    match block.open {
        None => block,
        Some(open) => {
            let found = header_found(open.kind, &open.value, open.overflow);
            let is_type = open.kind == Kind::Type;
            Block {
                open: None,
                message: block.message || found.message,
                digest: block.digest || found.digest,
                encoded: block.encoded || found.encoded,
                last_clear: if is_type {
                    Some(found.clear && !open.embedded)
                } else {
                    block.last_clear
                },
                ..block
            }
        }
    }
}


fn fresh_open(kind: Kind, rest: &[u8], cap: usize, embedded: bool) -> Open {
    append(
        Open {
            kind,
            value: Vec::new(),
            overflow: false,
            embedded,
        },
        rest,
        cap,
    )
}


fn absorb_embedded(block: Block, line: &[u8], cap: usize) -> Block {
    match embedded_header(line) {
        Some((kind, rest)) => close_header(Block {
            active: true,
            embedded: true,
            open: Some(fresh_open(kind, &rest, cap, true)),
            ..block
        }),
        None => block,
    }
}


fn open_header(block: Block, header: Option<(Kind, &[u8])>, line_start: usize, cap: usize) -> Block {
    match header {
        Some((kind, rest)) => Block {
            active: true,
            blank_from: block.blank_from.or(Some(line_start)),
            open: Some(fresh_open(kind, rest, cap, false)),
            ..block
        },
        None => block,
    }
}


fn finish(seen: Seen, end: usize, budgets: &Budgets) -> Result<Seen, Cut> {
    let block = close_header(seen.block);
    let default_clear = !(block.from_delimiter && seen.digest);
    let doubtful = block.last_clear.map_or(!default_clear, |clear| !clear);
    let candidate = block.suspect || block.message || doubtful;
    let nested = seen.nested + usize::from(candidate);
    let refuse = candidate && block.encoded;
    let blankable = block.blank_from.filter(|_| !block.embedded);
    if nested > budgets.nested || (refuse && blankable.is_none()) {
        Err(Cut {
            offset: block.start.unwrap_or(end),
            part: seen.blocks,
            refused: seen.refused,
        })
    } else {
        let mut refused = seen.refused;
        if let Some(from) = blankable.filter(|_| refuse) {
            refused.push(Refusal {
                range: from..end,
                part: seen.blocks,
            });
        }
        Ok(Seen {
            nested,
            digest: seen.digest || block.digest,
            blocks: seen.blocks + usize::from(block.active),
            region: candidate,
            block: Block::default(),
            refused,
            ..seen
        })
    }
}


fn is_relevant(block: &Block) -> bool {
    block.last_clear.is_some() || block.encoded
}


fn region_line(seen: Seen, line: &[u8], line_start: usize, budgets: &Budgets) -> Seen {
    let delimiter = line.starts_with(PART_PREFIX);
    let opens = !seen.region;
    let delimiter_like = delimiter || opens;
    let closed = close_header(seen.block);
    let relevant = is_relevant(&closed);
    let restarts = delimiter_like && !relevant;
    let base = if restarts { Block::default() } else { closed };
    let block = Block {
        start: if restarts { Some(line_start) } else { base.start.or(Some(line_start)) },
        suspect: base.suspect || (!opens && relevant && delimiter),
        from_delimiter: restarts || base.from_delimiter,
        ..base
    };
    let embedded = if delimiter_like {
        absorb_embedded(block, line, budgets.value_bytes)
    } else {
        block
    };
    Seen {
        region: true,
        block: open_header(embedded, header_of(line), line_start, budgets.value_bytes),
        ..seen
    }
}


fn header_line(seen: Seen, line: &[u8], budgets: &Budgets) -> Seen {
    let line_start = seen.offset;
    if seen.region || has_delimiter(line) {
        region_line(seen, line, line_start, budgets)
    } else {
        seen
    }
}


fn classify(seen: Seen, line: &[u8], budgets: &Budgets) -> Result<Seen, Cut> {
    let line_start = seen.offset;
    let end = line_start.saturating_add(line.len());
    let advanced = Seen { offset: end, ..seen.clone() };
    if is_folded(line) && seen.block.open.is_some() {
        let extended = seen.block.open.clone().map(|open| append(open, line, budgets.value_bytes));
        Ok(Seen {
            block: Block {
                open: extended,
                ..seen.block
            },
            ..advanced
        })
    } else if is_blank(line) && seen.region {
        finish(seen, line_start, budgets).map(|done| Seen { offset: end, ..done })
    } else if is_blank(line) {
        Ok(advanced)
    } else {
        let offset_kept = Seen { offset: line_start, ..seen };
        Ok(Seen {
            offset: end,
            ..header_line(offset_kept, line, budgets)
        })
    }
}


fn read_line(seen: Seen, line: &[u8], budgets: &Budgets) -> Result<Seen, Cut> {
    let header_lines = seen.header_lines + usize::from(is_header_line(line));
    let part_lines = seen.part_lines + usize::from(is_part_line(line));
    if header_lines > budgets.headers || part_lines > budgets.parts {
        Err(Cut {
            offset: seen.offset,
            part: seen.blocks,
            refused: seen.refused,
        })
    } else {
        classify(
            Seen {
                header_lines,
                part_lines,
                ..seen
            },
            line,
            budgets,
        )
    }
}


fn step(seen: Seen, line: Option<&[u8]>, budgets: &Budgets) -> Result<Seen, Cut> {
    match line {
        Some(bytes) => read_line(seen, bytes, budgets),
        None if seen.region && seen.block.start.is_some() => {
            let end = seen.offset;
            finish(seen, end, budgets)
        }
        None => Ok(seen),
    }
}


fn has_delimiter(line: &[u8]) -> bool {
    line.windows(PART_PREFIX.len()).any(|window| window == PART_PREFIX)
}


fn blanked(kept: &[u8], refused: &[Refusal]) -> Vec<u8> {
    let mut copy = kept.to_vec();
    refused.iter().for_each(|refusal| {
        copy.get_mut(refusal.range.clone())
            .into_iter()
            .flatten()
            .filter(|byte| **byte != CARRIAGE_RETURN && **byte != LINE_FEED)
            .for_each(|byte| *byte = BLANK);
    });
    copy
}


fn assemble(raw: &[u8], keep: usize, cut_part: Option<usize>, refused: Vec<Refusal>) -> Scan<'_> {
    let kept = raw.get(..keep).unwrap_or(raw);
    let lost_refused: usize = refused.iter().map(|refusal| refusal.range.len()).sum();
    let usable = if refused.is_empty() {
        Cow::Borrowed(kept)
    } else {
        Cow::Owned(blanked(kept, &refused))
    };
    Scan {
        usable,
        cut: cut_part.is_some(),
        refused: refused.len(),
        lost_bytes: raw.len().saturating_sub(kept.len()) + lost_refused,
        lost_part: refused.first().map(|refusal| refusal.part).or(cut_part),
    }
}


/// Cuts the raw message before the line or header block that exceeds a budget and blanks the headers of every encoded nested message, so the parser never copies more.
pub fn scan<'a>(raw: &'a [u8], limits: &Limits) -> Scan<'a> {
    let budgets = Budgets {
        headers: limits.headers.saturating_mul(limits.parts),
        parts: limits.parts.saturating_mul(NESTED_FACTOR),
        nested: limits.nested_messages,
        value_bytes: limits.header_bytes,
    };
    let mut lines = raw.split_inclusive(|byte| *byte == LINE_FEED).map(Some).chain(std::iter::once(None));
    let initial = Seen {
        region: true,
        ..Seen::default()
    };
    let outcome = lines.try_fold(initial, |seen, line| step(seen, line, &budgets));
    match outcome {
        Ok(done) => assemble(raw, raw.len(), None, done.refused),
        Err(cut) => assemble(raw, cut.offset, Some(cut.part), cut.refused),
    }
}
