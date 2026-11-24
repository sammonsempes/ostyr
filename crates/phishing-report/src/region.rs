use crate::limits::{Limits, MAX_HEADER_REGION_BYTES};
use crate::triage::{content_type_raws, parameter_pairs};
use mail_parser::{Header, HeaderName, Message, MessagePart, MimeHeaders, PartType};


const LF: u8 = b'\n';


const CR: u8 = b'\r';


const COLON: u8 = b':';


const DASHES: &[u8] = b"--";


const MBOX_FROM: &[u8] = b"From ";


const BOUNDARY_ATTRIBUTE: &str = "boundary";


const BOUNDARY_CONTINUATION: &str = "boundary*";


const ENCODED_WORD_MARK: &str = "=?";


const BACKSLASH: char = '\\';


#[derive(Debug, Clone, Copy)]
struct Walk {
    position: usize,
    next_header: usize,
    seen: bool,
}


fn is_blank(byte: &u8) -> bool {
    matches!(byte, b' ' | b'\t')
}


fn is_name_byte(byte: &u8) -> bool {
    (b'!'..=b'~').contains(byte)
}


fn trim_blank_end(bytes: &[u8]) -> &[u8] {
    bytes
        .split_at(bytes.iter().rposition(|byte| !is_blank(byte)).map_or(0, |last| last + 1))
        .0
}


fn base_of(message: &Message<'_>) -> usize {
    message.parts.first().map_or(0, |root| root.offset_header) as usize
}


fn relative(message: &Message<'_>, offset: u32) -> Option<usize> {
    (offset as usize).checked_sub(base_of(message))
}


fn header_line(walk: Walk, text: &[u8], headers: &[Header<'_>], start: usize) -> Option<usize> {
    let named = text
        .iter()
        .position(|byte| *byte == COLON)
        .and_then(|end| text.get(..end))
        .is_some_and(|name| !name.is_empty() && name.iter().all(is_name_byte));
    let listed = headers.get(walk.next_header);
    let mbox = start == 0 && text.starts_with(MBOX_FROM) && listed.is_some_and(|header| matches!(header.name, HeaderName::Other(_)));
    (named || mbox)
        .then(|| listed.filter(|header| header.offset_field as usize == start))
        .flatten()
        .map(|_| walk.next_header + 1)
}


fn step(walk: Walk, line: &[u8], headers: &[Header<'_>], first: usize) -> Option<Walk> {
    let body = line.strip_suffix(&[LF]).unwrap_or(line);
    let text = body.strip_suffix(&[CR]).unwrap_or(body);
    let moved = Walk {
        position: walk.position + line.len(),
        ..walk
    };
    let rejected = text.contains(&CR) || text.iter().all(is_blank) || text.starts_with(DASHES);
    if rejected {
        None
    } else if text.first().is_some_and(is_blank) {
        walk.seen.then_some(moved)
    } else {
        header_line(walk, text, headers, first + walk.position).map(|next_header| Walk {
            next_header,
            seen: !text.starts_with(MBOX_FROM),
            ..moved
        })
    }
}


/// Whether the header lines of `region` break the grammar or differ from the `headers` mail-parser listed; `first` is the stream offset of the region.
pub fn lines_ambiguous(region: &[u8], first: usize, headers: &[Header<'_>]) -> bool {
    let start = Walk {
        position: 0,
        next_header: 0,
        seen: false,
    };
    region
        .strip_suffix(&[LF])
        .and_then(|body| {
            let cut = body.iter().rposition(|byte| *byte == LF).map_or(0, |last| last + 1);
            let (lines, last) = body.split_at(cut);
            matches!(last, [] | [CR]).then_some(lines)
        })
        .and_then(|lines| {
            lines
                .split_inclusive(|byte| *byte == LF)
                .try_fold(start, |walk, line| step(walk, line, headers, first))
        })
        .is_none_or(|walk| walk.next_header != headers.len())
}


fn region_ambiguous(message: &Message<'_>, part: &MessagePart<'_>) -> bool {
    let region = relative(message, part.offset_header)
        .zip(relative(message, part.offset_body))
        .and_then(|(start, end)| message.raw_message().get(start..end));
    region.is_none_or(|bytes| bytes.len() > MAX_HEADER_REGION_BYTES || lines_ambiguous(bytes, part.offset_header as usize, part.headers()))
}


fn boundary_of<'a>(part: &'a MessagePart<'_>) -> Option<&'a str> {
    part.content_type().and_then(|content_type| content_type.attribute(BOUNDARY_ATTRIBUTE))
}


fn delimiter_ok(message: &Message<'_>, part: &MessagePart<'_>, parent: &MessagePart<'_>) -> bool {
    let before = relative(message, part.offset_header).and_then(|end| message.raw_message().get(..end));
    boundary_of(parent).zip(before).is_some_and(|(boundary, bytes)| {
        let line = bytes.strip_suffix(&[LF]).map(|rest| rest.strip_suffix(&[CR]).unwrap_or(rest));
        line.map(trim_blank_end)
            .and_then(|trimmed| trimmed.strip_suffix(boundary.as_bytes()))
            .and_then(|rest| rest.strip_suffix(DASHES))
            .is_some_and(|rest| rest.last() == Some(&LF) || base_of(message) + rest.len() == parent.offset_body as usize)
    })
}


fn is_parent_of(candidate: &MessagePart<'_>, index: usize) -> bool {
    match &candidate.body {
        PartType::Multipart(ids) => u32::try_from(index).is_ok_and(|id| ids.binary_search(&id).is_ok()),
        _ => false,
    }
}


fn delimiter_ambiguous(message: &Message<'_>, index: usize, part: &MessagePart<'_>) -> bool {
    let parent = message.parts.iter().take(index).rev().find(|candidate| is_parent_of(candidate, index));
    index > 0 && !parent.is_some_and(|found| delimiter_ok(message, part, found))
}


fn close_ok(message: &Message<'_>, container: &MessagePart<'_>, ids: &[u32]) -> bool {
    let end = ids
        .last()
        .and_then(|id| message.parts.get(*id as usize))
        .and_then(|child| relative(message, child.offset_end));
    let tail = end.and_then(|from| message.raw_message().get(from..));
    boundary_of(container).zip(tail).is_some_and(|(boundary, bytes)| {
        let after = bytes
            .strip_prefix(&[CR])
            .unwrap_or(bytes)
            .strip_prefix(&[LF])
            .and_then(|rest| rest.strip_prefix(DASHES))
            .and_then(|rest| rest.strip_prefix(boundary.as_bytes()))
            .and_then(|rest| rest.strip_prefix(DASHES))
            .map(|rest| rest.split_at(rest.iter().take_while(|byte| is_blank(byte)).count()).1);
        after.is_some_and(|rest| matches!(rest, [] | [LF, ..] | [CR, LF, ..]))
    })
}


fn boundary_text_ambiguous(raw: &str) -> bool {
    let names: Vec<String> = parameter_pairs(raw)
        .into_iter()
        .map(|(name, _)| name)
        .filter(|name| name.starts_with(BOUNDARY_ATTRIBUTE))
        .collect();
    raw.contains(BACKSLASH) || raw.contains(ENCODED_WORD_MARK) || names.len() > 1 || names.iter().any(|name| name.starts_with(BOUNDARY_CONTINUATION))
}


fn container_ambiguous(message: &Message<'_>, part: &MessagePart<'_>) -> bool {
    match &part.body {
        PartType::Multipart(ids) => {
            let raw_bad = content_type_raws(message, part)
                .next()
                .is_none_or(|raw| raw.and_then(|bytes| std::str::from_utf8(bytes).ok()).is_none_or(boundary_text_ambiguous));
            raw_bad || !close_ok(message, part, ids)
        }
        _ => false,
    }
}


fn part_ambiguous(message: &Message<'_>, index: usize, part: &MessagePart<'_>) -> bool {
    region_ambiguous(message, part)
        || content_type_raws(message, part).count() > 1
        || delimiter_ambiguous(message, index, part)
        || container_ambiguous(message, part)
}


/// How many of the first `limits.parts` parts of a message hold a header region that mail-parser and other MIME readers may read differently.
pub fn ambiguous_parts(message: &Message<'_>, limits: &Limits) -> usize {
    message
        .parts
        .iter()
        .take(limits.parts)
        .enumerate()
        .filter(|(index, part)| part_ambiguous(message, index.to_owned(), part))
        .count()
}
