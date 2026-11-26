//! Type aliases (Unix only).

use rustix::process::Pid;


/// Kills what is left of a child's process group; called while the leader is still an unreaped zombie.
pub type GroupKillFn = fn(Pid);
