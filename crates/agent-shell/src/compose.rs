use crate::model::{SharedHooks, ShellShared, ROOT_UID};
use std::path::PathBuf;
use std::sync::Mutex;


/// What every production session shares: the one-use store must belong to root, whatever the caller passes.
pub fn production_shared(agent_id: String, store_directory: PathBuf, hooks: SharedHooks<'_>) -> ShellShared<'_> {
    ShellShared {
        agent_id,
        store_directory,
        store_owner: ROOT_UID,
        store_lock: Mutex::new(()),
        clock: hooks.clock,
        dial: hooks.dial,
        attach: hooks.attach,
        enabled: hooks.enabled,
    }
}
