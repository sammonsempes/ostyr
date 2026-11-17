use crate::model::{
    ActionSpec, ConfigField, RawKey, Right, MAX_ACTIONS, MAX_CONFIG_FIELDS, MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES,
    MAX_OPENAPI_SERVERS, MAX_RIGHTS, MAX_TARGETS, MAX_TRUSTED_KEYS, MAX_VERSION_BYTES,
};
use semver::Version;
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess};
use serde_json::value::RawValue;
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


/// The outcome of a bounded read of untrusted input: the bound is decided from this value, never from an error text.
#[derive(Debug)]
pub enum Bounded<Element> {
    Within(Vec<Element>),
    Over { limit: usize },
}


impl<Element> Default for Bounded<Element> {
    fn default() -> Self {
        Self::Within(Vec::new())
    }
}


/// At most `max + 1` elements are built; a longer sequence is read to its end as `IgnoredAny` and reported as `Over`.
pub fn bounded_seq_outcome<'de, Source, Element>(deserializer: Source, max: usize) -> Result<Bounded<Element>, Source::Error>
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
            let over = items.len() > max;
            over.then(|| std::iter::from_fn(|| seq.next_element::<IgnoredAny>().transpose()).try_for_each(|rest| rest.map(|_| ())))
                .transpose()?;
            Ok(if over { Bounded::Over { limit: max } } else { Bounded::Within(items) })
        })
        .deserialize(deserializer)
}


/// The same bound for a map, keys as text; the entries after the cap are skipped without being built.
pub fn bounded_entries_outcome<'de, Source, Entry>(deserializer: Source, max: usize) -> Result<Bounded<(String, Entry)>, Source::Error>
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
            let over = entries.len() > max;
            over.then(|| {
                std::iter::from_fn(|| {
                    map.next_key::<IgnoredAny>()
                        .transpose()
                        .map(|key| key.and_then(|_| map.next_value::<IgnoredAny>()))
                })
                .try_for_each(|rest| rest.map(|_| ()))
            })
            .transpose()?;
            Ok(if over { Bounded::Over { limit: max } } else { Bounded::Within(entries) })
        })
        .deserialize(deserializer)
}


pub fn paths<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Bounded<(String, Box<RawValue>)>, Source::Error> {
    bounded_entries_outcome(deserializer, MAX_OPENAPI_PATHS)
}


pub fn schemes<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Bounded<(String, Box<RawValue>)>, Source::Error> {
    bounded_entries_outcome(deserializer, MAX_OPENAPI_SCHEMES)
}


pub fn parameters<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Bounded<Box<RawValue>>, Source::Error> {
    bounded_seq_outcome(deserializer, MAX_OPENAPI_PARAMETERS)
}


pub fn servers<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Bounded<Box<RawValue>>, Source::Error> {
    bounded_seq_outcome(deserializer, MAX_OPENAPI_SERVERS)
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
