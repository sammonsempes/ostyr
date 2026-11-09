use crate::model::{Channel, Message};


pub type Sender<'sender> = &'sender mut dyn FnMut(&Channel, &Message) -> Result<(), String>;


pub type Headers = Vec<(&'static str, zeroize::Zeroizing<String>)>;


pub type ClockFn<'clock> = &'clock dyn Fn() -> std::time::Instant;
