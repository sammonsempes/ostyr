use crate::model::{Item, Stream};
use crate::split::{step, take_partial};
use crate::utf16::{decode_chunk, stream_flawed};


pub fn feed_bytes(stream: &mut Stream, chunk: &[u8], emit: &mut dyn FnMut(Item)) {
    let splitter = &mut stream.splitter;
    decode_chunk(&mut stream.decoder, chunk, &mut |found, replaced| step(splitter, found, replaced, emit));
}


pub fn partial_item(stream: &mut Stream) -> Option<Item> {
    take_partial(&mut stream.splitter)
}


pub fn flawed(stream: &Stream) -> bool {
    stream_flawed(&stream.decoder)
}
