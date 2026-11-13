use crate::devices::{MAX_ADDRESSES, MAX_DEVICES_PER_FILE};
use crate::model::Device;
use serde::de::{Deserialize, Deserializer, Error, SeqAccess};
use serde_untagged::UntaggedEnumVisitor;
use std::net::IpAddr;


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
            (items.len() <= max).then_some(items).ok_or_else(|| Error::custom("too many elements"))
        })
        .deserialize(deserializer)
}


pub fn bounded_devices<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<Device>, Source::Error> {
    bounded_seq(deserializer, MAX_DEVICES_PER_FILE)
}


pub fn bounded_addresses<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<IpAddr>, Source::Error> {
    bounded_seq(deserializer, MAX_ADDRESSES)
}
