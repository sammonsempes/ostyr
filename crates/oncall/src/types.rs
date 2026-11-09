use crate::model::{Channel, Message};


pub type Sender<'sender> = &'sender mut dyn FnMut(&Channel, &Message) -> Result<(), String>;
