use crate::devices::{MAX_ADDRESSES, MAX_DEVICES_PER_FILE};
use crate::model::CountDevice;
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, SeqAccess};
use serde_untagged::UntaggedEnumVisitor;


/// The only message pass 1 can raise itself; every other pass 1 error is erased by the visitor and never shown.
pub const TOO_MANY_ELEMENTS: &str = "too many elements";


/// Reads at most `max + 1` elements of a sequence, so the element after the cap is never parsed, and refuses a longer sequence.
pub fn bounded_seq<'de, Source, Element>(deserializer: Source, max: usize) -> Result<Vec<Element>, Source::Error>
where
    Source: Deserializer<'de>,
    Element: Deserialize<'de>,
{
    UntaggedEnumVisitor::new()
        .expecting("a sequence")
        .seq(|mut seq| {
            let items = std::iter::from_fn(|| seq.next_element::<Element>().transpose())
                .take(max.saturating_add(1))
                .collect::<Result<Vec<Element>, _>>()?;
            (items.len() <= max).then_some(items).ok_or_else(|| Error::custom(TOO_MANY_ELEMENTS))
        })
        .deserialize(deserializer)
}


pub fn count_devices<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<CountDevice>, Source::Error> {
    bounded_seq(deserializer, MAX_DEVICES_PER_FILE)
}


pub fn count_addresses<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<IgnoredAny>, Source::Error> {
    bounded_seq(deserializer, MAX_ADDRESSES)
}
