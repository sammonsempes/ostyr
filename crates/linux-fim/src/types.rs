use crate::model::TracingPolicy;
use serde_saphyr::SerializeError;


/// Serialises a policy to text; a test double injects a failure.
pub type SerializeFn = fn(&TracingPolicy) -> Result<String, SerializeError>;


/// The kernel device number and the inode number of a file.
pub type Identity = (u32, u64);


/// Fills the buffer with random bytes; a test double injects a failure or fixed bytes.
#[cfg(target_os = "linux")]
pub type RandomFn = fn(&mut [u8]) -> std::io::Result<()>;


/// Gives a held file or directory to a user and sets its mode; a test double injects a failure.
#[cfg(target_os = "linux")]
pub type ClaimFn = fn(&std::os::fd::OwnedFd, u32, rustix::fs::RawMode) -> Result<(), rustix::io::Errno>;


/// Called with the held parent and the name of each directory the walk just opened; a test double swaps that name between two steps.
#[cfg(target_os = "linux")]
pub type StepFn = fn(&std::os::fd::OwnedFd, &str);


/// The text `tetra tracingpolicy list` prints; a test double injects a failure or a fixed listing.
#[cfg(target_os = "linux")]
pub type ListFn = fn() -> std::io::Result<String>;
