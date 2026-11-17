//! The `assets.owned_ratio` indicator, written in the JSON input format of the compliance evaluation (spec section 13).

use crate::config::{DECLARED_SOURCE, OWNER_ATTRIBUTE};
use crate::model::{Asset, Lifecycle, Snapshot};
use crate::reconcile::{check_identity, MAX_VALUE_BYTES};
use crate::types::TruthMap;
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


/// An owner counts when it comes from `declared` or the configured source of truth for `owner`, holds an ASCII alphanumeric and has unambiguous text.
pub fn is_owned(asset: &Asset, truth: &TruthMap) -> bool {
    asset.attributes.get(OWNER_ATTRIBUTE).is_some_and(|owner| {
        let trusted = owner.source == DECLARED_SOURCE || truth.get(OWNER_ATTRIBUTE).is_some_and(|source| *source == owner.source);
        trusted && owner.value.chars().any(|found| found.is_ascii_alphanumeric()) && check_identity("owner", &owner.value, MAX_VALUE_BYTES).is_ok()
    })
}


/// Counts in-service assets; one is owned when `is_owned` holds.
pub fn owned_ratio(snapshot: &Snapshot, truth: &TruthMap) -> Ratio {
    let in_service: Vec<&Asset> = snapshot.assets.iter().filter(|asset| is_in_service(asset)).collect();
    Ratio {
        owned: in_service.iter().filter(|asset| is_owned(asset, truth)).count(),
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
