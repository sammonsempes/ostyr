const COLON: u8 = b':';


const SEMICOLON: u8 = b';';


const SLASH: u8 = b'/';


const QUOTE: u8 = b'"';


const BACKSLASH: u8 = b'\\';


const OPEN_COMMENT: u8 = b'(';


const CLOSE_COMMENT: u8 = b')';


const SPACE: u8 = b' ';


const TAB: u8 = b'\t';


const NAME_SCAN: usize = 32;


const HALVES: usize = 2;


const TYPE_NAME: &[u8] = b"content-type";


const TYPE_HEADER: &[u8] = b"content-type:";


const ENCODING_HEADER: &[u8] = b"content-transfer-encoding:";


const TOKEN_PUNCTUATION: &[u8] = b"-.+";


const ENCODING_NAME: &[u8] = b"content-transfer-encoding";


const MESSAGE_WORD: &[u8] = b"message";


const DIGEST_WORD: &[u8] = b"digest";


const PLAIN_ENCODINGS: [&[u8]; 3] = [b"7bit", b"8bit", b"binary"];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Type,
    Encoding,
    Other,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Found {
    pub message: bool,
    pub digest: bool,
    pub clear: bool,
    pub encoded: bool,
}


/// A line that holds only whitespace ends a header block, as the parser reads it.
pub fn is_blank(line: &[u8]) -> bool {
    line.iter().all(|byte| byte.is_ascii_whitespace())
}


/// A line that starts with a space or a tab continues the header above it, as the parser unfolds it.
pub fn is_folded(line: &[u8]) -> bool {
    matches!(line.first(), Some(&SPACE | &TAB))
}


/// Reads a header line the way the parser does: whitespace inside the name is dropped and leading colons are skipped.
pub fn header_of(line: &[u8]) -> Option<(Kind, &[u8])> {
    let tail = line
        .iter()
        .position(|byte| !byte.is_ascii_whitespace() && *byte != COLON)
        .and_then(|start| line.get(start..))?;
    let colon = tail.iter().position(|byte| *byte == COLON)?;
    let name: Vec<u8> = tail
        .get(..colon)?
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(u8::to_ascii_lowercase)
        .take(NAME_SCAN)
        .collect();
    let kind = if name == TYPE_NAME {
        Kind::Type
    } else if name == ENCODING_NAME {
        Kind::Encoding
    } else {
        Kind::Other
    };
    Some((kind, tail.get(colon + 1..)?))
}


fn squeezed(head: &[u8]) -> Vec<u8> {
    head.iter()
        .filter(|byte| !byte.is_ascii_whitespace() && **byte != BACKSLASH && **byte != QUOTE)
        .map(u8::to_ascii_lowercase)
        .collect()
}


fn without_parentheses(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .filter(|byte| **byte != OPEN_COMMENT && **byte != CLOSE_COMMENT)
        .copied()
        .collect()
}


fn without_comments(bytes: &[u8]) -> Vec<u8> {
    let (_, kept) = bytes.iter().fold((0, Vec::new()), |(depth, mut kept): (usize, Vec<u8>), byte| {
        if *byte == OPEN_COMMENT {
            (depth + 1, kept)
        } else if *byte == CLOSE_COMMENT {
            (depth.saturating_sub(1), kept)
        } else {
            if depth == 0 {
                kept.push(*byte);
            }
            (depth, kept)
        }
    });
    kept
}


fn mentions(head: &[u8], word: &[u8]) -> bool {
    let squeezed_head = squeezed(head);
    [without_parentheses(&squeezed_head), without_comments(&squeezed_head), squeezed_head]
        .iter()
        .any(|view| view.windows(word.len()).any(|window| window == word))
}


fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(byte))
}


fn is_clear(head: &[u8]) -> bool {
    let mut halves = head.trim_ascii().splitn(HALVES, |byte| *byte == SLASH);
    match (halves.next(), halves.next()) {
        (Some(kind), Some(subtype)) => is_token(kind) && is_token(subtype) && !kind.eq_ignore_ascii_case(MESSAGE_WORD),
        _ => false,
    }
}


fn type_found(value: &[u8], overflow: bool) -> Found {
    let head = value.split(|byte| *byte == SEMICOLON).next().unwrap_or(value);
    Found {
        message: overflow || mentions(head, MESSAGE_WORD),
        digest: overflow || mentions(head, DIGEST_WORD),
        clear: !overflow && is_clear(head),
        encoded: false,
    }
}


fn encoding_found(value: &[u8], overflow: bool) -> Found {
    let trimmed: Vec<u8> = value
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(u8::to_ascii_lowercase)
        .collect();
    Found {
        encoded: overflow || (!trimmed.is_empty() && !PLAIN_ENCODINGS.contains(&trimmed.as_slice())),
        ..Found::default()
    }
}


/// What a finished header says about a nested message. A `Content-Type` is clear only as `token/token` before the first `;` and not `message`.
pub fn header_found(kind: Kind, value: &[u8], overflow: bool) -> Found {
    match kind {
        Kind::Type => type_found(value, overflow),
        Kind::Encoding => encoding_found(value, overflow),
        Kind::Other => Found::default(),
    }
}


/// A header the parser could read after a boundary on the same line: found by name anywhere in the line, whitespace removed.
pub fn embedded_header(line: &[u8]) -> Option<(Kind, Vec<u8>)> {
    let squeezed_line: Vec<u8> = line
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(u8::to_ascii_lowercase)
        .collect();
    [(Kind::Type, TYPE_HEADER), (Kind::Encoding, ENCODING_HEADER)]
        .iter()
        .find_map(|(kind, name)| {
            squeezed_line
                .windows(name.len())
                .position(|window| window == *name)
                .and_then(|at| squeezed_line.get(at + name.len()..))
                .map(|rest| (*kind, rest.to_vec()))
        })
}
