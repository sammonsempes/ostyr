//! Strict reading of an operator file that decides a security boundary: a byte allowlist, then a walk over the YAML events.

use crate::error::ConfigError;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle, ScanError, Span};


pub const TAGS_REFUSED: &str = "tags are not allowed";


pub const ESCAPES_REFUSED: &str = "escapes are not allowed in double-quoted strings";


pub const ANCHORS_REFUSED: &str = "anchors, aliases and merge keys are not allowed";


pub const BLOCKS_REFUSED: &str = "block scalars are not allowed";


pub const FLOW_REFUSED: &str = "flow collections are not allowed, write each entry in block style";


pub const FLOW_STARTS: [char; 2] = ['[', '{'];


pub const FIRST_PRINTABLE: u8 = 0x20;


pub const LAST_PRINTABLE: u8 = 0x7E;


pub const LINE_FEED: u8 = b'\n';


pub const CARRIAGE_RETURN: u8 = b'\r';


pub const KEY_VALUE_PAIR: usize = 2;


pub const MERGE_KEY: &str = "<<";


pub const ROOT_DEPTH: usize = 1;


pub const ENTRY_PARENT_DEPTH: usize = 2;


/// What the event walk checks: the root key whose list entries are numbered in refusals, the text of a parser error, flow admitted or not, line named or not.
#[derive(Debug, Clone, Copy)]
pub struct Rules<'a> {
    pub list_key: &'a str,
    pub invalid_text: &'a str,
    pub allow_flow: bool,
    pub show_line: bool,
}


/// Nesting depth, entries seen in the list and where the walk is in the root mapping, to name the entry that holds a refused feature.
#[derive(Debug, Clone, Copy)]
pub struct Walk {
    pub depth: usize,
    pub entries: usize,
    pub root_nodes: usize,
    pub list_key_seen: bool,
    pub in_list: bool,
}


pub const START: Walk = Walk {
    depth: 0,
    entries: 0,
    root_nodes: 0,
    list_key_seen: false,
    in_list: false,
};


pub fn refuse(file: &str, reason: String) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.to_owned(),
        reason,
    }
}


/// Whether the byte at `index` is allowed: printable ASCII, LF, or CR immediately followed by LF.
pub fn allowed_byte(bytes: &[u8], index: usize) -> bool {
    match bytes.get(index) {
        Some(&byte) if (FIRST_PRINTABLE..=LAST_PRINTABLE).contains(&byte) || byte == LINE_FEED => true,
        Some(&byte) if byte == CARRIAGE_RETURN => bytes.get(index.saturating_add(1)) == Some(&LINE_FEED),
        _ => false,
    }
}


/// Refuses the whole file on the first byte outside the allowlist, naming the line (counted on LF), never the content.
pub fn refuse_forbidden_bytes(text: &str, file: &str) -> Result<(), ConfigError> {
    let bytes = text.as_bytes();
    match (0..bytes.len()).find(|&index| !allowed_byte(bytes, index)) {
        Some(index) => {
            let line = bytes
                .get(..index)
                .map_or(0, |head| head.iter().filter(|&&byte| byte == LINE_FEED).count())
                .saturating_add(1);
            Err(refuse(file, format!("line {line}: only printable ASCII and line breaks are allowed")))
        }
        None => Ok(()),
    }
}


pub fn is_node_start(event: &Event<'_>) -> bool {
    matches!(event, Event::Scalar(..) | Event::SequenceStart(..) | Event::MappingStart(..))
}


/// The fixed reason an event is refused for, if any: a tag, an anchor, an alias, a merge key, a block scalar, an escape, and a flow collection unless admitted.
pub fn feature_reason(event: &Event<'_>, span: &Span, text: &str, allow_flow: bool) -> Option<&'static str> {
    match event {
        Event::Scalar(_, _, _, Some(_)) | Event::SequenceStart(_, _, Some(_)) | Event::MappingStart(_, _, Some(_)) => Some(TAGS_REFUSED),
        Event::Scalar(_, _, anchor, _) | Event::SequenceStart(_, anchor, _) | Event::MappingStart(_, anchor, _) if *anchor != 0 => {
            Some(ANCHORS_REFUSED)
        }
        Event::Alias(_) | Event::UnresolvedAlias(_) => Some(ANCHORS_REFUSED),
        Event::SequenceStart(..) | Event::MappingStart(..)
            if !allow_flow && span.slice(text).is_none_or(|source| source.starts_with(FLOW_STARTS)) =>
        {
            Some(FLOW_REFUSED)
        }
        Event::Scalar(_, ScalarStyle::Literal | ScalarStyle::Folded, _, _) => Some(BLOCKS_REFUSED),
        Event::Scalar(value, _, _, _) if value == MERGE_KEY => Some(ANCHORS_REFUSED),
        Event::Scalar(_, ScalarStyle::DoubleQuoted, _, _) if span.slice(text).is_none_or(|source| source.contains('\\')) => Some(ESCAPES_REFUSED),
        _ => None,
    }
}


/// Where the node that starts in the root mapping sits: keys are even nodes, values odd; only the value of the list key is inside the entries.
pub fn track_root(walk: Walk, event: &Event<'_>, list_key: &str) -> Walk {
    let at_root = walk.depth == ROOT_DEPTH && is_node_start(event);
    let is_value = at_root && walk.root_nodes % KEY_VALUE_PAIR == 1;
    let is_list_key = at_root && !is_value && matches!(event, Event::Scalar(value, ..) if value == list_key);
    Walk {
        root_nodes: walk.root_nodes.saturating_add(usize::from(at_root)),
        list_key_seen: if at_root && !is_value { is_list_key } else { walk.list_key_seen },
        in_list: if at_root { is_value && walk.list_key_seen } else { walk.in_list },
        entries: if is_value { 0 } else { walk.entries },
        ..walk
    }
}


/// The text of a refusal: the entry index when the feature is inside an entry of the list, never the value; the line when the rules ask for it.
pub fn feature_refusal(walk: Walk, reason: &str, line: usize, rules: Rules<'_>) -> String {
    let named = if walk.in_list && walk.entries > 0 {
        format!("{}[{}]: {reason}", rules.list_key, walk.entries.saturating_sub(1))
    } else {
        reason.to_owned()
    };
    if rules.show_line {
        format!("line {line}: {named}")
    } else {
        named
    }
}


/// One parser event: refuses the features, tracks the nesting and the entry count.
pub fn walk_step(walk: Walk, item: Result<(Event<'_>, Span), ScanError>, text: &str, file: &str, rules: Rules<'_>) -> Result<Walk, ConfigError> {
    let (event, span) = item.map_err(|_| refuse(file, rules.invalid_text.to_owned()))?;
    let tracked = track_root(walk, &event, rules.list_key);
    let started = Walk {
        entries: tracked.entries.saturating_add(usize::from(
            tracked.in_list && tracked.depth == ENTRY_PARENT_DEPTH && is_node_start(&event),
        )),
        ..tracked
    };
    match (feature_reason(&event, &span, text, rules.allow_flow), &event) {
        (Some(reason), _) => Err(refuse(file, feature_refusal(started, reason, span.start.line(), rules))),
        (None, Event::SequenceStart(..) | Event::MappingStart(..)) => Ok(Walk {
            depth: started.depth.saturating_add(1),
            ..started
        }),
        (None, Event::SequenceEnd | Event::MappingEnd) => Ok(Walk {
            depth: started.depth.saturating_sub(1),
            ..started
        }),
        (None, _) => Ok(started),
    }
}


/// Refuses every YAML tag, anchor, alias, merge key, block scalar and double-quoted escape (and flow collections unless admitted) before any typed pass.
pub fn refuse_features(text: &str, file: &str, rules: Rules<'_>) -> Result<(), ConfigError> {
    Parser::new_from_str(text)
        .try_fold(START, |walk, item| walk_step(walk, item, text, file, rules))
        .map(drop)
}
