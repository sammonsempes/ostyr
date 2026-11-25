#![cfg(unix)]
use backup_monitor::borg::BorgError;
use backup_monitor::secrets::{
    open_secret_in, open_secret_in_with, open_secrets_dir, secret_path, secret_refusal, valid_secret_name, SecretsDir, MAX_SECRET_NAME_BYTES,
};
use core_config::secret_file::SecretFileError;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{create_dir, set_permissions, File, Metadata, Permissions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;
use tempfile::TempDir;


const PRIVATE_MODE: u32 = 0o700;


const SECRET_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const OPEN_MODE: u32 = 0o755;


const HANG_GUARD: Duration = Duration::from_secs(20);


struct Setup {
    dir: TempDir,
    directory: PathBuf,
    secrets: SecretsDir,
}


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn setup() -> Result<Setup, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let directory = dir.path().join("secrets");
    create_dir(&directory)?;
    set_permissions(&directory, Permissions::from_mode(PRIVATE_MODE))?;
    let password = directory.join("password");
    std::fs::write(&password, "hunter2\n")?;
    set_permissions(&password, Permissions::from_mode(SECRET_MODE))?;
    let secrets = open_secrets_dir(&directory, euid())?;
    Ok(Setup { dir, directory, secrets })
}


fn failing(_handle: &File) -> io::Result<Metadata> {
    Err(io::Error::other("inspection failed"))
}


#[test]
fn names_are_plain_file_names_only() -> Result<(), Box<dyn Error>> {
    ["password", "a.b-c_d", "A1", "x.y.z"]
        .iter()
        .for_each(|name| assert!(valid_secret_name(name), "{name}"));
    let long = "a".repeat(MAX_SECRET_NAME_BYTES + 1);
    let at_cap = "a".repeat(MAX_SECRET_NAME_BYTES);
    [
        "",
        ".",
        "..",
        "a/b",
        "../x",
        "/etc/passwd",
        "a ",
        "a b",
        "a.",
        "caf\u{e9}",
        "a\u{3164}",
        "a\nb",
        "a:b",
        &long,
    ]
    .iter()
    .for_each(|name| assert!(!valid_secret_name(name), "{name:?}"));
    assert!(valid_secret_name(&at_cap));
    Ok(())
}


#[test]
fn the_directory_must_be_trusted_exactly_private_and_text() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    assert!(matches!(open_secrets_dir(Path::new("relative"), euid()), Err(BorgError::BaseDir)));
    assert!(matches!(
        open_secrets_dir(&setup.dir.path().join("absent"), euid()),
        Err(BorgError::BaseDir)
    ));
    assert!(matches!(
        open_secrets_dir(&setup.directory.join("password"), euid()),
        Err(BorgError::BaseDir)
    ));
    set_permissions(&setup.directory, Permissions::from_mode(OPEN_MODE))?;
    assert!(matches!(open_secrets_dir(&setup.directory, euid()), Err(BorgError::BaseDir)));
    set_permissions(&setup.directory, Permissions::from_mode(PRIVATE_MODE))?;
    let link = setup.dir.path().join("link");
    symlink(&setup.directory, &link)?;
    assert!(matches!(open_secrets_dir(&link, euid()), Err(BorgError::BaseDir)));
    let binary = setup.dir.path().join(OsStr::from_bytes(b"caf\xe9"));
    create_dir(&binary)?;
    set_permissions(&binary, Permissions::from_mode(PRIVATE_MODE))?;
    assert!(matches!(open_secrets_dir(&binary, euid()), Err(BorgError::BaseDir)));
    Ok(())
}


#[test]
fn a_secret_path_is_built_only_from_a_plain_name() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    assert_eq!(
        secret_path(&setup.secrets, "password"),
        Some(setup.directory.join("password").display().to_string())
    );
    ["../password", "a/b", "", "..", "/etc/passwd"]
        .iter()
        .for_each(|name| assert_eq!(secret_path(&setup.secrets, name), None, "{name}"));
    Ok(())
}


#[test]
fn a_good_secret_opens_and_every_bad_one_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    open_secret_in(&setup.secrets, "password", euid())?;
    symlink(setup.directory.join("password"), setup.directory.join("link"))?;
    create_dir(setup.directory.join("directory"))?;
    let loose = setup.directory.join("loose");
    std::fs::write(&loose, "x")?;
    set_permissions(&loose, Permissions::from_mode(GROUP_READABLE_MODE))?;
    assert!(matches!(
        open_secret_in(&setup.secrets, "link", euid()),
        Err(SecretFileError::Symlink { .. })
    ));
    assert!(matches!(
        open_secret_in(&setup.secrets, "directory", euid()),
        Err(SecretFileError::NotRegular { .. })
    ));
    assert!(matches!(
        open_secret_in(&setup.secrets, "loose", euid()),
        Err(SecretFileError::Mode { .. })
    ));
    assert!(matches!(
        open_secret_in(&setup.secrets, "absent", euid()),
        Err(SecretFileError::Io { .. })
    ));
    assert!(matches!(
        open_secret_in_with(&setup.secrets, "password", euid(), failing),
        Err(SecretFileError::Io { .. })
    ));
    Ok(())
}


#[test]
fn a_name_with_a_separator_never_opens_a_file_outside_the_directory() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let outside = setup.dir.path().join("outside");
    std::fs::write(&outside, "hunter2\n")?;
    set_permissions(&outside, Permissions::from_mode(SECRET_MODE))?;
    ["../outside", "sub/../../outside", "..", "", "/etc/hostname"].iter().for_each(|name| {
        assert!(
            matches!(open_secret_in(&setup.secrets, name, euid()), Err(SecretFileError::NotRegular { .. })),
            "{name}"
        )
    });
    Ok(())
}


#[test]
fn a_refusal_has_a_fixed_category_without_the_file_name() -> Result<(), Box<dyn Error>> {
    let io_error = SecretFileError::Io {
        file: "NAMEMARKER".to_owned(),
        source: io::Error::other("x"),
    };
    let refusals = [
        (io_error, "unreadable"),
        (
            SecretFileError::NotRegular {
                file: "NAMEMARKER".to_owned(),
            },
            "not a regular file",
        ),
        (
            SecretFileError::Symlink {
                file: "NAMEMARKER".to_owned(),
            },
            "symlink",
        ),
        (
            SecretFileError::Mode {
                file: "NAMEMARKER".to_owned(),
            },
            "mode",
        ),
        (
            SecretFileError::Owner {
                file: "NAMEMARKER".to_owned(),
            },
            "owner",
        ),
    ];
    refusals.iter().for_each(|(error, expected)| {
        let category = secret_refusal(error);
        assert_eq!(category, *expected);
        assert!(!category.contains("NAMEMARKER"));
    });
    Ok(())
}


#[test]
fn a_secret_with_another_hard_link_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    open_secret_in(&setup.secrets, "password", euid())?;
    std::fs::hard_link(setup.directory.join("password"), setup.dir.path().join("elsewhere"))?;
    assert!(matches!(
        open_secret_in(&setup.secrets, "password", euid()),
        Err(SecretFileError::NotRegular { .. })
    ));
    Ok(())
}


#[test]
fn a_fifo_secret_is_refused_at_once_and_never_blocks_the_open() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let pipe = setup.directory.join("pipe");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &pipe,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )?;
    let (sender, receiver) = channel();
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| sender.send(open_secret_in(&setup.secrets, "pipe", euid()).map(|_file| ())));
        let answer = receiver.recv_timeout(HANG_GUARD);
        if answer.is_err() {
            let released = std::fs::OpenOptions::new().write(true).open(&pipe);
            assert!(released.is_ok(), "the guard could not release the blocked open");
        }
        answer
    });
    assert!(
        matches!(outcome, Ok(Err(SecretFileError::NotRegular { .. }))),
        "the open of a FIFO must return a refusal at once, got {outcome:?}"
    );
    Ok(())
}
