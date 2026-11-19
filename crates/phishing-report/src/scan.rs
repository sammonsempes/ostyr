use crate::limits::Limits;
use crate::mime::{header_flags, header_of, is_blank, is_folded, Flags, Kind};
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
}


#[derive(Debug, Clone, Default)]
struct Block {
    active: bool,
    start: usize,
    index: usize,
    open: Option<Open>,
    flags: Flags,
}


#[derive(Debug, Clone, Default)]
struct Seen {
    offset: usize,
    header_lines: usize,
    part_lines: usize,
    nested: usize,
    digest: bool,
    blocks: usize,
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
            let found = header_flags(open.kind, &open.value, open.overflow);
            Block {
                open: None,
                flags: Flags {
                    message: block.flags.message || found.message,
                    digest: block.flags.digest || found.digest,
                    other: block.flags.other || found.other,
                    encoded: block.flags.encoded || found.encoded,
                },
                ..block
            }
        }
    }
}


fn start_header(block: Block, header: Option<(Kind, &[u8])>, offset: usize, index: usize, cap: usize) -> Block {
    let closed = close_header(block);
    match header {
        Some((kind, rest)) => {
            let fresh = Open {
                kind,
                value: Vec::new(),
                overflow: false,
            };
            Block {
                active: true,
                start: if closed.active { closed.start } else { offset },
                index: if closed.active { closed.index } else { index },
                open: Some(append(fresh, rest, cap)),
                ..closed
            }
        }
        None => closed,
    }
}


fn finish(seen: Seen, end: usize, budgets: &Budgets) -> Result<Seen, Cut> {
    let block = close_header(seen.block);
    if block.active {
        let encoded_nested = block.flags.encoded && (block.flags.message || (seen.digest && !block.flags.other));
        let nested = seen.nested + usize::from(block.flags.message || encoded_nested);
        if nested > budgets.nested {
            Err(Cut {
                offset: block.start,
                part: block.index,
                refused: seen.refused,
            })
        } else {
            let mut refused = seen.refused;
            if encoded_nested {
                refused.push(Refusal {
                    range: block.start..end,
                    part: block.index,
                });
            }
            Ok(Seen {
                nested,
                digest: seen.digest || block.flags.digest,
                block: Block::default(),
                refused,
                ..seen
            })
        }
    } else {
        Ok(Seen {
            block: Block::default(),
            ..seen
        })
    }
}


fn classify(seen: Seen, line: &[u8], budgets: &Budgets) -> Result<Seen, Cut> {
    let line_start = seen.offset;
    let end = line_start.saturating_add(line.len());
    let header = header_of(line);
    if is_folded(line) && seen.block.open.is_some() {
        let extended = seen.block.open.clone().map(|open| append(open, line, budgets.value_bytes));
        Ok(Seen {
            offset: end,
            block: Block {
                open: extended,
                ..seen.block
            },
            ..seen
        })
    } else if is_blank(line) {
        finish(seen, line_start, budgets).map(|done| Seen { offset: end, ..done })
    } else {
        let blocks = seen.blocks + usize::from(!seen.block.active && header.is_some());
        let block = start_header(seen.block, header, line_start, seen.blocks, budgets.value_bytes);
        Ok(Seen {
            offset: end,
            blocks,
            block,
            ..seen
        })
    }
}


fn read_line(seen: Seen, line: &[u8], budgets: &Budgets) -> Result<Seen, Cut> {
    let header_lines = seen.header_lines + usize::from(is_header_line(line));
    let part_lines = seen.part_lines + usize::from(is_part_line(line));
    let nested = seen.nested + usize::from(seen.digest && line.starts_with(PART_PREFIX));
    if header_lines > budgets.headers || part_lines > budgets.parts || nested > budgets.nested {
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
                nested,
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
        None => {
            let end = seen.offset;
            finish(seen, end, budgets)
        }
    }
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
    let outcome = lines.try_fold(Seen::default(), |seen, line| step(seen, line, &budgets));
    match outcome {
        Ok(done) => assemble(raw, raw.len(), None, done.refused),
        Err(cut) => assemble(raw, cut.offset, Some(cut.part), cut.refused),
    }
}
