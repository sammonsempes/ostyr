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


const TYPE_NAME: &[u8] = b"content-type";


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
pub struct Flags {
    pub message: bool,
    pub digest: bool,
    pub other: bool,
    pub encoded: bool,
}


#[derive(Debug, Clone, Default)]
struct Walk {
    depth: usize,
    escaped: bool,
    ended: bool,
    current: Vec<u8>,
    segments: Vec<Vec<u8>>,
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


fn walk_byte(walk: Walk, byte: u8) -> Walk {
    if walk.ended {
        walk
    } else if walk.depth > 0 {
        let opens = byte == OPEN_COMMENT && !walk.escaped;
        let closes = byte == CLOSE_COMMENT && !walk.escaped;
        Walk {
            depth: walk.depth + usize::from(opens) - usize::from(closes),
            escaped: byte == BACKSLASH && !walk.escaped,
            ..walk
        }
    } else if byte == OPEN_COMMENT || byte == SLASH {
        let mut segments = walk.segments;
        segments.push(walk.current);
        Walk {
            depth: usize::from(byte == OPEN_COMMENT),
            escaped: false,
            current: Vec::new(),
            segments,
            ..walk
        }
    } else if byte == SEMICOLON {
        Walk { ended: true, ..walk }
    } else if byte.is_ascii_whitespace() || byte == QUOTE {
        walk
    } else {
        let mut current = walk.current;
        current.push(byte.to_ascii_lowercase());
        Walk { current, ..walk }
    }
}


/// The words of a `Content-Type` value, split at every comment and slash, so "message", "message(x)/rfc822" and a folded form all show.
fn type_segments(value: &[u8]) -> Vec<Vec<u8>> {
    let walked = value.iter().fold(Walk::default(), |walk, byte| walk_byte(walk, *byte));
    let mut segments = walked.segments;
    segments.push(walked.current);
    segments
}


fn type_flags(value: &[u8], overflow: bool) -> Flags {
    let segments = type_segments(value);
    let message = overflow || segments.iter().any(|segment| segment == MESSAGE_WORD);
    Flags {
        message,
        digest: overflow || segments.iter().any(|segment| segment == DIGEST_WORD),
        other: !overflow && !message && segments.first().is_some_and(|first| !first.is_empty()),
        encoded: false,
    }
}


fn encoding_flags(value: &[u8], overflow: bool) -> Flags {
    let trimmed: Vec<u8> = value
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(u8::to_ascii_lowercase)
        .collect();
    Flags {
        encoded: overflow || (!trimmed.is_empty() && !PLAIN_ENCODINGS.contains(&trimmed.as_slice())),
        ..Flags::default()
    }
}


/// What a finished header says about a nested message: any transfer encoding but 7bit, 8bit and binary is encoded; a value too long to read counts as every flag.
pub fn header_flags(kind: Kind, value: &[u8], overflow: bool) -> Flags {
    match kind {
        Kind::Type => type_flags(value, overflow),
        Kind::Encoding => encoding_flags(value, overflow),
        Kind::Other => Flags::default(),
    }
}
