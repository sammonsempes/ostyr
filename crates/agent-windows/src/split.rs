use crate::model::{Item, Splitter, MAX_ITEM_BYTES, MAX_SYSTEM_BYTES};


const START: &[u8] = b"<Event";


const END: &[u8] = b"</Event>";


pub fn is_delimiter(byte: u8) -> bool {
    matches!(byte, b' ' | b'>' | b'\t' | b'\r' | b'\n')
}


pub fn advance(pattern: &[u8], progress: usize, byte: u8) -> usize {
    if pattern.get(progress) == Some(&byte) {
        progress + 1
    } else if pattern.first() == Some(&byte) {
        1
    } else {
        0
    }
}


pub fn head_of(item: &[u8]) -> Vec<u8> {
    item.iter().take(MAX_SYSTEM_BYTES).copied().collect()
}


pub fn advance_start(splitter: &mut Splitter, byte: u8) -> bool {
    let waiting = splitter.start_match == START.len();
    let found = waiting && is_delimiter(byte);
    let from = if waiting { 0 } else { splitter.start_match };
    splitter.start_match = advance(START, from, byte);
    found
}


pub fn advance_end(splitter: &mut Splitter, byte: u8) -> bool {
    splitter.end_match = advance(END, splitter.end_match, byte);
    let found = splitter.end_match == END.len();
    splitter.end_match = if found { 0 } else { splitter.end_match };
    found
}


pub fn begin(splitter: &mut Splitter, delimiter: u8) {
    splitter.inside = true;
    splitter.item = START.iter().copied().chain(std::iter::once(delimiter)).collect();
    splitter.size = splitter.item.len();
    splitter.nested = false;
    splitter.end_match = 0;
}


pub fn finish(splitter: &mut Splitter) -> Item {
    let item = std::mem::take(&mut splitter.item);
    let size = splitter.size;
    let nested = splitter.nested;
    splitter.inside = false;
    splitter.size = 0;
    splitter.nested = false;
    splitter.end_match = 0;
    if nested {
        Item::Nested { head: head_of(&item), size }
    } else if size > MAX_ITEM_BYTES {
        Item::Oversized { head: head_of(&item), size }
    } else {
        Item::Complete(item)
    }
}


pub fn step(splitter: &mut Splitter, byte: u8, emit: &mut dyn FnMut(Item)) {
    let was_inside = splitter.inside;
    if was_inside {
        splitter.size += 1;
        if splitter.item.len() < MAX_ITEM_BYTES {
            splitter.item.push(byte);
        }
    }
    let start_found = advance_start(splitter, byte);
    let end_found = was_inside && advance_end(splitter, byte);
    if start_found && was_inside {
        splitter.nested = true;
    }
    if start_found && !was_inside {
        begin(splitter, byte);
    }
    if end_found {
        emit(finish(splitter));
    }
}


pub fn feed(splitter: &mut Splitter, chunk: &[u8], emit: &mut dyn FnMut(Item)) {
    chunk.iter().for_each(|byte| step(splitter, *byte, emit));
}


pub fn take_partial(splitter: &mut Splitter) -> Option<Item> {
    let partial = splitter.inside.then(|| Item::Oversized {
        head: head_of(&splitter.item),
        size: splitter.size,
    });
    *splitter = Splitter::default();
    partial
}
