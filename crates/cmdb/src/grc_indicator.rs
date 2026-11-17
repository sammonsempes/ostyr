//! The `assets.owned_ratio` indicator, written in the JSON input format of the compliance evaluation (spec section 13).

use crate::config::OWNER_ATTRIBUTE;
use crate::model::{Asset, Lifecycle, Snapshot};
use serde_json::{json, Value};


pub const INDICATOR_NAME: &str = "assets.owned_ratio";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ratio {
    pub owned: usize,
    pub total: usize,
}


pub fn is_in_service(asset: &Asset) -> bool {
    asset.lifecycle == Lifecycle::InService
}


pub fn is_owned(asset: &Asset) -> bool {
    asset.attributes.get(OWNER_ATTRIBUTE).is_some_and(|owner| !owner.value.trim().is_empty())
}


/// Counts in-service assets; one is owned when its `owner` attribute is present and not blank.
pub fn owned_ratio(snapshot: &Snapshot) -> Ratio {
    let in_service: Vec<&Asset> = snapshot.assets.iter().filter(|asset| is_in_service(asset)).collect();
    Ratio {
        owned: in_service.iter().filter(|asset| is_owned(asset)).count(),
        total: in_service.len(),
    }
}


/// An empty inventory gives an empty list: no value, so the control is not assessable.
pub fn indicator_json(tenant: &str, ratio: &Ratio, observed_at: &str, source: &str) -> String {
    let values: Vec<Value> = if ratio.total == 0 {
        Vec::new()
    } else {
        vec![json!({
            "tenant": tenant,
            "name": INDICATOR_NAME,
            "value": ratio.owned as f64 / ratio.total as f64,
            "observed_at": observed_at,
            "source": source,
        })]
    };
    Value::Array(values).to_string()
}
