//! Host side of the eBPF probes; the kernel object lives in `ebpf/` and is not a workspace member.

pub mod btf;
pub mod btf_file;
pub mod drain;
#[cfg(target_os = "linux")]
pub mod error;
pub mod limiter;
pub mod loader;
#[cfg(target_os = "linux")]
pub mod object;
pub mod record;
#[cfg(target_os = "linux")]
pub mod shape;
pub mod types;
