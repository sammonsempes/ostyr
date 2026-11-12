use crate::types::{ServiceRatios, TraceId};
use core_config::error::ConfigError;
use core_config::parse::parse_document;
use serde::Deserialize;
use thiserror::Error;


pub const MAX_SAMPLING_SERVICES: usize = 256;


pub const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;


pub const RATIO_NONE: f64 = 0.0;


pub const RATIO_ALL: f64 = 1.0;


pub const HASH_BYTES: usize = 8;


#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sampling {
    pub default_ratio: f64,
    pub services: ServiceRatios,
    pub error_ratio: Option<f64>,
}


impl Default for Sampling {
    fn default() -> Self {
        Self {
            default_ratio: RATIO_ALL,
            services: ServiceRatios::new(),
            error_ratio: None,
        }
    }
}


#[derive(Debug, Error)]
pub enum SamplingError {
    #[error("the sampling file is not valid")]
    Parse(#[from] ConfigError),
    #[error("the sampling ratio {field} is outside 0 to 1")]
    Ratio { field: &'static str },
    #[error("the sampling file names more than {MAX_SAMPLING_SERVICES} services")]
    TooManyServices,
    #[error("error_ratio is below a ratio it overrides")]
    ErrorRatioBelowRatio,
}


pub fn ratio_valid(ratio: f64) -> bool {
    (RATIO_NONE..=RATIO_ALL).contains(&ratio)
}


pub fn validate_sampling(sampling: &Sampling) -> Result<(), SamplingError> {
    let services_valid = sampling.services.values().all(|ratio| ratio_valid(*ratio));
    let floor = sampling
        .services
        .values()
        .fold(sampling.default_ratio, |highest, ratio| highest.max(*ratio));
    if !ratio_valid(sampling.default_ratio) {
        Err(SamplingError::Ratio { field: "default_ratio" })
    } else if !services_valid {
        Err(SamplingError::Ratio { field: "services" })
    } else if sampling.error_ratio.is_some_and(|error_ratio| !ratio_valid(error_ratio)) {
        Err(SamplingError::Ratio { field: "error_ratio" })
    } else if sampling.services.len() > MAX_SAMPLING_SERVICES {
        Err(SamplingError::TooManyServices)
    } else if sampling.error_ratio.is_some_and(|error_ratio| error_ratio < floor) {
        Err(SamplingError::ErrorRatioBelowRatio)
    } else {
        Ok(())
    }
}


/// Parses and validates the sampling file text; `file` only labels errors.
pub fn parse_sampling(text: &str, file: &str) -> Result<Sampling, SamplingError> {
    let sampling = parse_document::<Sampling>(text, file)?;
    validate_sampling(&sampling).map(|()| sampling)
}


/// The first 8 bytes of the trace id as a big-endian u64: OTLP trace ids are random, so it is uniform.
pub fn trace_hash(trace_id: &TraceId) -> u64 {
    let mut head = [u8::MIN; HASH_BYTES];
    head.iter_mut().zip(trace_id.iter()).for_each(|(slot, byte)| *slot = *byte);
    u64::from_be_bytes(head)
}


/// The ratio that applies to one span: the error ratio for an error span, else the service override, else the default.
pub fn ratio_for(sampling: &Sampling, service: &str, is_error: bool) -> f64 {
    let base = sampling.services.get(service).copied().unwrap_or(sampling.default_ratio);
    match sampling.error_ratio {
        Some(error_ratio) if is_error => error_ratio,
        _ => base,
    }
}


/// `keep = hash(trace_id) < ratio * 2^64`: every span of a trace with the same ratio gets the same decision.
pub fn keep_span(sampling: &Sampling, service: &str, trace_id: &TraceId, is_error: bool) -> bool {
    let threshold = (ratio_for(sampling, service, is_error) * TWO_POW_64) as u128;
    u128::from(trace_hash(trace_id)) < threshold
}
