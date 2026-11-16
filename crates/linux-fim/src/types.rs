use crate::model::TracingPolicy;
use serde_saphyr::SerializeError;


/// Serialises a policy to text; a test double injects a failure.
pub type SerializeFn = fn(&TracingPolicy) -> Result<String, SerializeError>;
