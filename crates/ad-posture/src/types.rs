use crate::error::EntryError;
use crate::model::Entry;
use serde_json::value::RawValue;


/// One entry with its position and the raw token it came from.
pub type Outcome<'a> = (usize, &'a RawValue, Result<Entry, EntryError>);
