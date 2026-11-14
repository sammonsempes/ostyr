use crate::model::SkipReason;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use serde_with::{DeserializeAs, Map, Same};


fn unparsable(_error: serde_json::Error) -> SkipReason {
    SkipReason::Unparsable
}


fn within(count: usize, cap: usize) -> Result<usize, SkipReason> {
    if count > cap {
        Err(SkipReason::BadField)
    } else {
        Ok(count)
    }
}


/// Entries of a JSON array counted without allocating (`IgnoredAny` is zero-sized); an absent or null array is empty, one above `cap` is refused.
pub fn counted_array(raw: Option<&RawValue>, cap: usize) -> Result<usize, SkipReason> {
    let count = raw
        .map_or(Ok(0), |value| {
            serde_json::from_str::<Vec<IgnoredAny>>(value.get()).map(|entries| entries.len())
        })
        .map_err(unparsable)?;
    within(count, cap)
}


/// Entries of a JSON object counted without allocating (a duplicate key counts each time); an absent or null object is empty, one above `cap` is refused.
pub fn counted_map(raw: Option<&RawValue>, cap: usize) -> Result<usize, SkipReason> {
    let count = raw
        .map_or(Ok(0), |value| {
            let mut counter = serde_json::Deserializer::from_str(value.get());
            Map::<Same, Same>::deserialize_as(&mut counter).map(|entries: Vec<(IgnoredAny, IgnoredAny)>| entries.len())
        })
        .map_err(unparsable)?;
    within(count, cap)
}


/// The values of an object whose key count was checked first (`counted_map`), so the vector is bounded by that cap.
pub fn map_values(raw: Option<&RawValue>) -> Result<Vec<&RawValue>, SkipReason> {
    let entries = raw
        .map_or(Ok(Vec::new()), |value| {
            let mut reader = serde_json::Deserializer::from_str(value.get());
            Map::<Same, Same>::deserialize_as(&mut reader)
        })
        .map_err(unparsable)?;
    Ok(entries.into_iter().map(|(_key, value): (IgnoredAny, &RawValue)| value).collect())
}
