use crate::types::TestResult;
use agent_shell::account::{Databases, HomeFacts};
use agent_shell::cgroup::production_host;
use agent_shell::error::{AccountError, ShellError};
use agent_shell::hooks::{hooks_with, production_hooks};
use std::io;
use std::path::Path;


const ACCOUNT_UID: u32 = 1001;


const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\n";


const GROUP: &str = "root:x:0:\nostyr-shell:x:1002:\n";


fn databases() -> io::Result<Databases> {
    Ok(Databases {
        passwd: PASSWD.to_owned(),
        group: GROUP.to_owned(),
    })
}


fn owned_home(_home: &Path) -> io::Result<HomeFacts> {
    Ok(HomeFacts {
        is_directory: true,
        owner: ACCOUNT_UID,
    })
}


#[test]
fn both_hooks_come_from_one_resolution_with_its_uid() -> TestResult {
    let hooks = hooks_with("ostyr-shell", databases, owned_home, production_host())?;
    assert_eq!(hooks.uid, ACCOUNT_UID);
    assert!(matches!(
        hooks_with("nobody-like-it", databases, owned_home, production_host()),
        Err(ShellError::Account(AccountError::Missing { .. }))
    ));
    Ok(())
}


#[test]
fn the_production_builder_reads_the_local_databases() -> TestResult {
    assert!(matches!(
        production_hooks("ostyr-no-such-account-name"),
        Err(ShellError::Account(AccountError::Missing { .. }))
    ));
    assert_eq!(
        production_hooks("ostyr-no-such-account-name").err().map(|error| error.to_string()),
        Some("the shell account is refused: the shell account ostyr-no-such-account-name does not exist".to_owned())
    );
    Ok(())
}
