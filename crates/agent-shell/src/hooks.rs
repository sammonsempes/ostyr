use crate::account::{read_databases, resolve_account, stat_home, ShellAccount};
use crate::cgroup::{production_host, CgroupHost};
use crate::cleanup::cleanup_fn;
use crate::error::ShellError;
use crate::model::SessionHooks;
use crate::spawn::spawn_fn;
use crate::types::{DatabasesFn, HomeFn};


/// Both hooks of a session from its one account resolution.
pub fn session_hooks(account: ShellAccount, host: CgroupHost) -> SessionHooks {
    SessionHooks {
        uid: account.uid,
        cleanup: cleanup_fn(&account, host.clone()),
        spawn: spawn_fn(account, host),
    }
}


/// Resolves the account once and builds the spawn and the cleanup from that one result.
pub fn hooks_with(name: &str, read: DatabasesFn, home: HomeFn, host: CgroupHost) -> Result<SessionHooks, ShellError> {
    resolve_account(name, read, home)
        .map(|account| session_hooks(account, host))
        .map_err(ShellError::from)
}


/// The production `BuildFn`: the local databases, the real home check and the real cgroup host.
pub fn production_hooks(name: &str) -> Result<SessionHooks, ShellError> {
    hooks_with(name, read_databases, stat_home, production_host())
}
