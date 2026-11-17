use crate::model::{
    ActionSpec, ConfigField, RawKey, Right, MAX_ACTIONS, MAX_CONFIG_FIELDS, MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES,
    MAX_OPENAPI_SERVERS, MAX_RIGHTS, MAX_TARGETS, MAX_TRUSTED_KEYS, MAX_VERSION_BYTES,
};
use crate::openapi::{Parameter, PathItem, Scheme, Server};
use semver::Version;
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess};
use serde_untagged::UntaggedEnumVisitor;


pub const TOO_MANY_ELEMENTS: &str = "too many elements";


/// Reads at most `max + 1` elements of a sequence, so the element after the cap is never built, and refuses a longer sequence.
pub fn bounded_seq<'de, Source, Element>(deserializer: Source, max: usize) -> Result<Vec<Element>, Source::Error>
where
    Source: Deserializer<'de>,
    Element: Deserialize<'de>,
{
    bounded_seq_named(deserializer, max, TOO_MANY_ELEMENTS)
}


/// The same bound with a fixed message that names the collection.
pub fn bounded_seq_named<'de, Source, Element>(deserializer: Source, max: usize, message: &'static str) -> Result<Vec<Element>, Source::Error>
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
            (items.len() <= max).then_some(items).ok_or_else(|| Error::custom(message))
        })
        .deserialize(deserializer)
}


/// Reads at most `max + 1` entries of a map, keys as text, so the entry after the cap is never built, and refuses a longer map.
pub fn bounded_entries<'de, Source, Entry>(deserializer: Source, max: usize, message: &'static str) -> Result<Vec<(String, Entry)>, Source::Error>
where
    Source: Deserializer<'de>,
    Entry: Deserialize<'de>,
{
    UntaggedEnumVisitor::new()
        .expecting("a map")
        .map(|mut map| {
            let entries = std::iter::from_fn(|| map.next_entry::<String, Entry>().transpose())
                .take(max.saturating_add(1))
                .collect::<Result<Vec<(String, Entry)>, _>>()?;
            (entries.len() <= max).then_some(entries).ok_or_else(|| Error::custom(message))
        })
        .deserialize(deserializer)
}


pub const TOO_MANY_PATHS: &str = "too many paths";


pub const TOO_MANY_PARAMETERS: &str = "too many parameters";


pub const TOO_MANY_SCHEMES: &str = "too many security schemes";


pub const TOO_MANY_SERVERS: &str = "too many servers";


pub fn paths<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<(String, PathItem)>, Source::Error> {
    bounded_entries(deserializer, MAX_OPENAPI_PATHS, TOO_MANY_PATHS)
}


pub fn schemes<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<(String, Scheme)>, Source::Error> {
    bounded_entries(deserializer, MAX_OPENAPI_SCHEMES, TOO_MANY_SCHEMES)
}


pub fn parameters<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<Parameter>, Source::Error> {
    bounded_seq_named(deserializer, MAX_OPENAPI_PARAMETERS, TOO_MANY_PARAMETERS)
}


pub fn servers<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Vec<Server>, Source::Error> {
    bounded_seq_named(deserializer, MAX_OPENAPI_SERVERS, TOO_MANY_SERVERS)
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
