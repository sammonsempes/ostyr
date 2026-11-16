use crate::model::{
    ActionSpec, ConfigField, RawKey, Right, MAX_ACTIONS, MAX_CONFIG_FIELDS, MAX_RIGHTS, MAX_TARGETS, MAX_TRUSTED_KEYS, MAX_VERSION_BYTES,
};
use semver::Version;
use serde::de::{Deserialize, Deserializer, Error, SeqAccess};
use serde_untagged::UntaggedEnumVisitor;


pub const TOO_MANY_ELEMENTS: &str = "too many elements";


/// Reads at most `max + 1` elements of a sequence, so the element after the cap is never built, and refuses a longer sequence.
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


pub fn rights<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<Right>, Source::Error> {
    bounded_seq(deserializer, MAX_RIGHTS)
}


pub fn actions<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<ActionSpec>, Source::Error> {
    bounded_seq(deserializer, MAX_ACTIONS)
}


pub fn config<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<ConfigField>, Source::Error> {
    bounded_seq(deserializer, MAX_CONFIG_FIELDS)
}


pub fn targets<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<String>, Source::Error> {
    bounded_seq(deserializer, MAX_TARGETS)
}


pub fn keys<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<RawKey>, Source::Error> {
    bounded_seq(deserializer, MAX_TRUSTED_KEYS)
}


pub const VERSION_TOO_LONG: &str = "invalid `version`: too long";


/// A version text over `MAX_VERSION_BYTES` is refused before semver parsing.
pub fn version<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Version, Source::Error> {
    UntaggedEnumVisitor::new()
        .expecting("a version")
        .string(|text| {
            (text.len() <= MAX_VERSION_BYTES)
                .then_some(text)
                .ok_or_else(|| Error::custom(VERSION_TOO_LONG))
                .and_then(|short| Version::parse(short).map_err(Error::custom))
        })
        .deserialize(deserializer)
}
