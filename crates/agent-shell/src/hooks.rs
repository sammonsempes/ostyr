use crate::account::{read_databases, resolve_in, stat_home, ShellAccount};
use crate::cgroup::{production_host, CgroupHost};
use crate::cleanup::{cleanup_fn, running_fn};
use crate::error::{AccountError, ShellError};
use crate::model::SessionHooks;
use crate::spawn::spawn_fn;
use crate::types::{DatabasesFn, HomeFn};


/// Both hooks of a session from its one account resolution.
pub fn session_hooks(account: ShellAccount, host: CgroupHost) -> SessionHooks {
    SessionHooks {
        uid: account.uid,
        running: running_fn(account.uid),
        cleanup: cleanup_fn(&account, host.clone()),
        spawn: spawn_fn(account, host),
    }
}


/// Reads the databases once and resolves the account from that text.
pub fn hooks_with(name: &str, read: DatabasesFn, home: HomeFn, host: CgroupHost) -> Result<SessionHooks, ShellError> {
    let databases = read().map_err(AccountError::Lookup)?;
    let account = resolve_in(name, &databases, home)?;
    Ok(session_hooks(account, host))
}


/// The production `BuildFn`: the local databases, the real home check and the real cgroup host.
pub fn production_hooks(name: &str) -> Result<SessionHooks, ShellError> {
    hooks_with(name, read_databases, stat_home, production_host())
}
