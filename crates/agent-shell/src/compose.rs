use crate::model::{ShellEnv, ShellHooks, ROOT_UID};
use std::path::PathBuf;
use std::sync::Mutex;


/// The environment of a production session: the one-use store must belong to root, whatever the caller passes.
pub fn production_env(agent_id: String, store_directory: PathBuf, hooks: ShellHooks<'_>) -> ShellEnv<'_> {
    ShellEnv {
        agent_id,
        store_directory,
        store_owner: ROOT_UID,
        store_lock: Mutex::new(()),
        clock: hooks.clock,
        dial: hooks.dial,
        spawn: hooks.spawn,
        attach: hooks.attach,
        cleanup: hooks.cleanup,
    }
}
