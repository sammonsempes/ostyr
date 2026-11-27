use crate::limits::SHA256_BYTES;
use crate::model::{ToolOutput, TracingPolicy};
use serde_saphyr::SerializeError;


/// Serialises a policy to text; a test double injects a failure.
pub type SerializeFn = fn(&TracingPolicy) -> Result<String, SerializeError>;


/// A SHA-256 digest.
pub type Sha256Digest = [u8; SHA256_BYTES];


/// Runs one package tool (binary path, arguments); a test double returns a canned output or an error.
pub type RunFn = fn(&str, &[&str]) -> std::io::Result<ToolOutput>;


/// The kernel device and inode a path names now, without following a final link; a test double injects a failure or a swap.
pub type IdentityFn = fn(&str) -> std::io::Result<Identity>;


/// Whether a path exists; a test double stands for a Debian or a Red Hat family host.
pub type ExistsFn = fn(&str) -> bool;


/// The text of a symbolic link, `None` when the path is not a link; a test double stands for a merged or a split `/usr`.
pub type LinkFn = fn(&str) -> Option<String>;


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
