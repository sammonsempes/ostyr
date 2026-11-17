use crate::model::TracingPolicy;
use serde_saphyr::SerializeError;


/// Serialises a policy to text; a test double injects a failure.
pub type SerializeFn = fn(&TracingPolicy) -> Result<String, SerializeError>;


/// The kernel device number and the inode number of a file.
pub type Identity = (u32, u64);
