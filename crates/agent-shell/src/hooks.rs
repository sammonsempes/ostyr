use crate::account::{read_databases, resolve_in, stat_home, uid_holders, ShellAccount};
use crate::cgroup::{production_host, CgroupHost};
use crate::cleanup::cleanup_fn;
use crate::error::{AccountError, ShellError};
use crate::model::SessionHooks;
use crate::spawn::spawn_fn;
use crate::types::{DatabasesFn, HomeFn};


/// Both hooks of a session from its one account resolution.
pub fn session_hooks(account: ShellAccount, previous_holders: usize, host: CgroupHost) -> SessionHooks {
    SessionHooks {
        uid: account.uid,
        previous_holders,
        cleanup: cleanup_fn(&account, host.clone()),
        spawn: spawn_fn(account, host),
    }
}


/// Reads the databases once, resolves the account from that text and counts, in the same text, the passwd lines that hold the previous uid.
pub fn hooks_with(name: &str, previous: Option<u32>, read: DatabasesFn, home: HomeFn, host: CgroupHost) -> Result<SessionHooks, ShellError> {
    let databases = read().map_err(AccountError::Lookup)?;
    let held = previous
        .map_or(Ok(0), |uid| uid_holders(&databases.passwd, uid))
        .map_err(AccountError::Lookup)?;
    let account = resolve_in(name, &databases, home)?;
    Ok(session_hooks(account, held, host))
}


/// The production `BuildFn`: the local databases, the real home check and the real cgroup host.
pub fn production_hooks(name: &str, previous: Option<u32>) -> Result<SessionHooks, ShellError> {
    hooks_with(name, previous, read_databases, stat_home, production_host())
}
