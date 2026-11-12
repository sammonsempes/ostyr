use crate::error::GrcError;
use crate::model::Evidence;
use sha2::{Digest, Sha256};


const ZERO: f64 = 0.0;


/// Decimal text of a value: shortest round-trip form, so `1.0` and `1` agree, and negative zero reads as zero.
pub fn canonical_value(value: f64) -> String {
    format!("{}", value + ZERO)
}


/// Fixed field order, every text field length-prefixed so no field can shift into its neighbour.
pub fn canonical_text(indicator: &str, value: f64, observed_at: i64, source: &str) -> String {
    format!(
        "indicator={}:{};value={};observed_at={};source={}:{}",
        indicator.len(),
        indicator,
        canonical_value(value),
        observed_at,
        source.len(),
        source
    )
}


pub fn digest_of(indicator: &str, value: f64, observed_at: i64, source: &str) -> String {
    Sha256::digest(canonical_text(indicator, value, observed_at, source).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}


pub fn make_evidence(indicator: &str, value: f64, observed_at: i64, source: &str) -> Evidence {
    Evidence {
        indicator: indicator.to_owned(),
        value,
        observed_at,
        source: source.to_owned(),
        sha256: digest_of(indicator, value, observed_at, source),
    }
}


/// Recomputes the digest from the fields; any changed field is `EvidenceMismatch`.
pub fn verify_evidence(evidence: &Evidence) -> Result<(), GrcError> {
    if digest_of(&evidence.indicator, evidence.value, evidence.observed_at, &evidence.source) == evidence.sha256 {
        Ok(())
    } else {
        Err(GrcError::EvidenceMismatch)
    }
}
