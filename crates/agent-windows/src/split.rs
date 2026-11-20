use crate::model::{Item, ItemKind, Splitter, MAX_ITEM_BYTES, MAX_SYSTEM_BYTES};


const START: [char; 6] = ['<', 'E', 'v', 'e', 'n', 't'];


const END: [char; 8] = ['<', '/', 'E', 'v', 'e', 'n', 't', '>'];


pub fn is_delimiter(found: char) -> bool {
    matches!(found, ' ' | '>' | '\t' | '\r' | '\n')
}


pub fn advance(pattern: &[char], progress: usize, found: char) -> usize {
    if pattern.get(progress) == Some(&found) {
        progress + 1
    } else if pattern.first() == Some(&found) {
        1
    } else {
        0
    }
}


pub fn head_of(item: &str) -> String {
    let end = (0..=MAX_SYSTEM_BYTES.min(item.len()))
        .rev()
        .find(|at| item.is_char_boundary(*at))
        .unwrap_or(0);
    item.split_at(end).0.to_string()
}


pub fn advance_start(splitter: &mut Splitter, found: char) -> bool {
    let waiting = splitter.start_match == START.len();
    let matched = waiting && is_delimiter(found);
    let from = if waiting { 0 } else { splitter.start_match };
    splitter.start_match = advance(&START, from, found);
    matched
}


pub fn advance_end(splitter: &mut Splitter, found: char) -> bool {
    splitter.end_match = advance(&END, splitter.end_match, found);
    let matched = splitter.end_match == END.len();
    splitter.end_match = if matched { 0 } else { splitter.end_match };
    matched
}


pub fn begin(splitter: &mut Splitter, delimiter: char) {
    splitter.inside = true;
    splitter.item = START.iter().copied().chain(std::iter::once(delimiter)).collect();
    splitter.size = splitter.item.len();
    splitter.nested = false;
    splitter.end_match = 0;
    splitter.replaced = 0;
}


pub fn finish(splitter: &mut Splitter) -> Item {
    let text = std::mem::take(&mut splitter.item);
    let size = splitter.size;
    let nested = splitter.nested;
    let replaced = splitter.replaced;
    splitter.inside = false;
    splitter.size = 0;
    splitter.nested = false;
    splitter.end_match = 0;
    splitter.replaced = 0;
    if nested {
        Item {
            kind: ItemKind::Nested,
            text: head_of(&text),
            size,
            replaced,
        }
    } else if size > MAX_ITEM_BYTES {
        Item {
            kind: ItemKind::Oversized,
            text: head_of(&text),
            size,
            replaced,
        }
    } else {
        Item {
            kind: ItemKind::Complete,
            text,
            size,
            replaced,
        }
    }
}


pub fn step(splitter: &mut Splitter, found: char, was_replaced: bool, emit: &mut dyn FnMut(Item)) {
    let was_inside = splitter.inside;
    if was_inside {
        splitter.size += found.len_utf8();
        splitter.replaced += u32::from(was_replaced);
        if splitter.item.len() < MAX_ITEM_BYTES {
            splitter.item.push(found);
        }
    }
    let start_found = advance_start(splitter, found);
    let end_found = was_inside && advance_end(splitter, found);
    if start_found && was_inside {
        splitter.nested = true;
    }
    if start_found && !was_inside {
        begin(splitter, found);
    }
    if end_found {
        emit(finish(splitter));
    }
}


pub fn take_partial(splitter: &mut Splitter) -> Option<Item> {
    let partial = splitter.inside.then(|| Item {
        kind: ItemKind::Oversized,
        text: head_of(&splitter.item),
        size: splitter.size,
        replaced: splitter.replaced,
    });
    *splitter = Splitter::default();
    partial
}
