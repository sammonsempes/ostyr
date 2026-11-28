#![cfg(unix)]


use attack_paths::error::{SealError, TagsError};
use attack_paths::input::Stamp;
use attack_paths::model::MAX_TAGS;
use attack_paths::seal::{
    apply_attributes, current_uid, parse_seal_arguments, refuse_unsafe_directory, refuse_unsafe_file, seal_tags, seal_with, write_sealed,
    DirectoryFacts, PERMISSION_BITS, ROOT_UID,
};
use attack_paths::serve::run;
use attack_paths::tags::{load_tags, sealed_text};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-attack-paths");


const OWNER_ONLY: u32 = 0o600;


const GROUP_READABLE: u32 = 0o640;


const GROUP_WRITABLE: u32 = 0o660;


const OPEN_DIRECTORY: u32 = 0o770;


const PRIVATE_DIRECTORY: u32 = 0o700;


const FOREIGN_UID: u32 = 12_345;


const TAGS_IN_BODY: usize = 2;


const GROUP_WRITE_DIRECTORY: u32 = 0o720;


const OTHER_WRITE_DIRECTORY: u32 = 0o702;


const GROUP_WRITE_FILE: u32 = 0o620;


const OTHER_WRITE_FILE: u32 = 0o602;


const OTHER_UID: u32 = 1_000;


const BODY: &str = "critical:\n  - Admins\n  - Backup\n";


struct FailingOutput;


impl Write for FailingOutput {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}


fn seal_file(file: &Path, flags: &[&str]) -> Result<Result<String, SealError>, Box<dyn std::error::Error>> {
    let name = file.display().to_string();
    let mut arguments = flags.to_vec();
    arguments.push(&name);
    let mut out = Vec::new();
    let outcome = seal_with(&words(&arguments), &mut out, |_path| Ok(()), current_uid());
    Ok(outcome.map(|()| String::from_utf8_lossy(&out).trim_end().to_string()))
}


fn put(dir: &Path, name: &str, text: &str, mode: u32) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let file = dir.join(name);
    fs::write(&file, text)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(mode))?;
    Ok(file)
}


fn leftovers(dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let names: Result<Vec<String>, io::Error> = fs::read_dir(dir)?
        .map(|entry| entry.map(|each| each.file_name().to_string_lossy().to_string()))
        .collect();
    Ok(names?.into_iter().filter(|name| name.starts_with(".tmp")).collect())
}


#[test]
fn the_arguments_are_pinned() -> TestResult {
    assert_eq!(parse_seal_arguments(&words(&["/a/tags.yaml"]))?.file, Path::new("/a/tags.yaml"));
    assert!(!parse_seal_arguments(&words(&["/a/tags.yaml"]))?.reseal);
    assert!(parse_seal_arguments(&words(&["--reseal", "/a/tags.yaml"]))?.reseal);
    [
        words(&[]),
        words(&["--reseal"]),
        words(&["relative.yaml"]),
        words(&["--reseal", "relative.yaml"]),
        words(&["/a", "/b"]),
        words(&["--force", "/a"]),
        words(&["/a", "--reseal"]),
        words(&["--reseal", "--reseal", "/a"]),
    ]
    .iter()
    .try_for_each(|arguments| -> TestResult {
        assert!(matches!(parse_seal_arguments(arguments), Err(SealError::Usage)), "{arguments:?}");
        Ok(())
    })
}


#[test]
fn a_fresh_file_is_sealed_through_a_rename_and_keeps_its_mode() -> TestResult {
    let dir = tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    let file = put(dir.path(), "tags.yaml", BODY, GROUP_READABLE)?;
    let before = fs::metadata(&file)?.ino();
    assert_eq!(seal_file(&file, &[])??, "sealed: 2 tags sealed");
    assert_eq!(fs::read_to_string(&file)?, sealed_text(BODY));
    assert_ne!(fs::metadata(&file)?.ino(), before);
    assert_eq!(fs::metadata(&file)?.mode() & PERMISSION_BITS, GROUP_READABLE);
    assert_eq!(load_tags(&file)?.critical, vec!["Admins".to_string(), "Backup".to_string()]);
    assert!(leftovers(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn a_sealed_file_needs_reseal_and_an_unchanged_one_is_not_rewritten() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", &sealed_text(BODY), OWNER_ONLY)?;
    assert!(matches!(seal_file(&file, &[])?, Err(SealError::AlreadySealed)));
    let inode = fs::metadata(&file)?.ino();
    assert_eq!(seal_file(&file, &["--reseal"])??, "unchanged");
    assert_eq!(fs::metadata(&file)?.ino(), inode);
    Ok(())
}


#[test]
fn reseal_of_an_edited_or_torn_file_says_the_body_changed() -> TestResult {
    let dir = tempdir()?;
    let edited = put(dir.path(), "edited.yaml", &sealed_text(BODY).replace("Backup", "Vault"), OWNER_ONLY)?;
    assert_eq!(seal_file(&edited, &["--reseal"])??, "body changed since the last seal: 2 tags sealed");
    assert_eq!(fs::read_to_string(&edited)?, sealed_text("critical:\n  - Admins\n  - Vault\n"));
    let torn = put(dir.path(), "torn.yaml", &format!("{BODY}complete: sha256:abc\n"), OWNER_ONLY)?;
    assert_eq!(seal_file(&torn, &["--reseal"])??, "body changed since the last seal: 2 tags sealed");
    assert_eq!(load_tags(&torn)?.critical.len(), TAGS_IN_BODY);
    Ok(())
}


#[test]
fn a_body_that_is_not_a_clean_tag_list_is_refused_and_nothing_is_written() -> TestResult {
    let dir = tempdir()?;
    let many = format!("critical:\n{}", "  - a\n".repeat(MAX_TAGS + 1));
    let cases = [
        ("crlf.yaml", "critical:\r\n  - a\r\n".to_string()),
        ("lone.yaml", "critical:\r  - a\n".to_string()),
        ("nonewline.yaml", "critical: []".to_string()),
        ("unknown.yaml", "important: [a]\n".to_string()),
        ("many.yaml", many),
    ];
    cases.iter().try_for_each(|(name, text)| -> TestResult {
        let file = put(dir.path(), name, text, OWNER_ONLY)?;
        assert!(seal_file(&file, &[])?.is_err(), "{name}");
        assert!(seal_file(&file, &["--reseal"])?.is_err(), "{name}");
        assert_eq!(&fs::read_to_string(&file)?, text);
        Ok(())
    })?;
    let crlf = put(dir.path(), "again.yaml", "a: 1\r\n", OWNER_ONLY)?;
    assert!(matches!(seal_file(&crlf, &[])?, Err(SealError::Tags(TagsError::CarriageReturn))));
    let bare = put(dir.path(), "bare.yaml", "critical: []", OWNER_ONLY)?;
    assert!(matches!(seal_file(&bare, &[])?, Err(SealError::NoFinalNewline)));
    assert!(leftovers(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn an_empty_file_is_sealed_as_no_manual_tags() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", "", OWNER_ONLY)?;
    assert_eq!(seal_file(&file, &[])??, "sealed: 0 tags sealed");
    assert_eq!(fs::read_to_string(&file)?, sealed_text(""));
    Ok(())
}


#[test]
fn a_symlink_a_fifo_a_directory_and_a_missing_file_are_refused() -> TestResult {
    let dir = tempdir()?;
    let target = put(dir.path(), "target.yaml", BODY, OWNER_ONLY)?;
    let link = dir.path().join("link.yaml");
    symlink(&target, &link)?;
    assert!(matches!(seal_file(&link, &[])?, Err(SealError::Tags(TagsError::Config(_)))));
    let fifo = dir.path().join("fifo.yaml");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(seal_file(&fifo, &[])?, Err(SealError::Tags(TagsError::Config(_)))));
    assert!(matches!(seal_file(dir.path(), &[])?, Err(SealError::Tags(TagsError::Config(_)))));
    assert!(matches!(
        seal_file(&dir.path().join("absent.yaml"), &[])?,
        Err(SealError::Tags(TagsError::Config(_)))
    ));
    assert_eq!(fs::read_to_string(&target)?, BODY);
    Ok(())
}


fn append_during_read(path: &Path) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(b"#\n")
}


#[test]
fn a_file_that_changes_during_the_read_is_refused_with_nothing_written() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let name = file.display().to_string();
    let mut out = Vec::new();
    let outcome = seal_with(&words(&[&name]), &mut out, append_during_read, current_uid());
    assert!(matches!(outcome, Err(SealError::Tags(TagsError::Changed))));
    assert!(out.is_empty());
    assert_eq!(fs::read_to_string(&file)?, format!("{BODY}#\n"));
    assert!(leftovers(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn a_group_writable_directory_or_file_is_refused_with_nothing_written() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, GROUP_WRITABLE)?;
    assert!(matches!(seal_file(&file, &[])?, Err(SealError::UnsafeFile)));
    assert_eq!(fs::read_to_string(&file)?, BODY);
    fs::set_permissions(&file, fs::Permissions::from_mode(OWNER_ONLY))?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    assert!(matches!(seal_file(&file, &[])?, Err(SealError::UnsafeDirectory)));
    assert_eq!(fs::read_to_string(&file)?, BODY);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    assert!(leftovers(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn the_directory_rule_is_checked_on_its_facts() -> TestResult {
    let caller = OTHER_UID;
    let good = DirectoryFacts {
        is_directory: true,
        mode: PRIVATE_DIRECTORY,
        owner: caller,
    };
    assert!(refuse_unsafe_directory(&good, caller).is_ok());
    assert!(refuse_unsafe_directory(&DirectoryFacts { owner: ROOT_UID, ..good }, caller).is_ok());
    assert!(refuse_unsafe_directory(&DirectoryFacts { owner: caller, ..good }, ROOT_UID).is_err());
    [
        DirectoryFacts { is_directory: false, ..good },
        DirectoryFacts {
            mode: GROUP_WRITE_DIRECTORY,
            ..good
        },
        DirectoryFacts {
            mode: OTHER_WRITE_DIRECTORY,
            ..good
        },
        DirectoryFacts { owner: FOREIGN_UID, ..good },
    ]
    .iter()
    .try_for_each(|facts| -> TestResult {
        assert!(
            matches!(refuse_unsafe_directory(facts, caller), Err(SealError::UnsafeDirectory)),
            "{facts:?}"
        );
        Ok(())
    })?;
    assert!(refuse_unsafe_file(OWNER_ONLY).is_ok());
    assert!(refuse_unsafe_file(GROUP_READABLE).is_ok());
    assert!(matches!(refuse_unsafe_file(GROUP_WRITE_FILE), Err(SealError::UnsafeFile)));
    assert!(matches!(refuse_unsafe_file(OTHER_WRITE_FILE), Err(SealError::UnsafeFile)));
    Ok(())
}


fn stamp_of_mode(mode: u32) -> Stamp {
    Stamp {
        size: 0,
        modified: (0, 0),
        changed: (0, 0),
        mode,
        owner: current_uid(),
        group: 0,
    }
}


#[test]
fn a_symlink_planted_at_the_name_is_replaced_never_followed() -> TestResult {
    let dir = tempdir()?;
    let victim = put(dir.path(), "victim.yaml", "keep: me\n", OWNER_ONLY)?;
    let name = dir.path().join("tags.yaml");
    symlink(&victim, &name)?;
    write_sealed(&name, &sealed_text(BODY), &stamp_of_mode(OWNER_ONLY), current_uid())?;
    assert_eq!(fs::read_to_string(&victim)?, "keep: me\n");
    assert!(!fs::symlink_metadata(&name)?.file_type().is_symlink());
    assert_eq!(fs::read_to_string(&name)?, sealed_text(BODY));
    Ok(())
}


#[test]
fn a_failed_rename_leaves_no_temporary_file_and_a_missing_directory_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let blocking = dir.path().join("occupied");
    fs::create_dir(&blocking)?;
    fs::write(blocking.join("inside"), "x")?;
    let refused = write_sealed(&blocking, &sealed_text(BODY), &stamp_of_mode(OWNER_ONLY), current_uid());
    assert!(matches!(refused, Err(SealError::Io(_))));
    assert!(leftovers(dir.path())?.is_empty());
    let nowhere = dir.path().join("absent").join("tags.yaml");
    assert!(matches!(
        write_sealed(&nowhere, "x", &stamp_of_mode(OWNER_ONLY), current_uid()),
        Err(SealError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_caller_playing_root_restores_the_owner_and_group_of_the_old_file() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let metadata = fs::metadata(&file)?;
    let name = file.display().to_string();
    let mut out = Vec::new();
    seal_with(&words(&[&name]), &mut out, |_path| Ok(()), ROOT_UID)?;
    let after = fs::metadata(&file)?;
    assert_eq!((after.uid(), after.gid()), (metadata.uid(), metadata.gid()));
    assert_eq!(fs::read_to_string(&file)?, sealed_text(BODY));
    Ok(())
}


#[test]
fn a_caller_that_is_not_root_sets_the_mode_and_never_tries_to_chown() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let before = fs::metadata(&file)?;
    let stamp = Stamp {
        owner: FOREIGN_UID,
        group: FOREIGN_UID,
        ..stamp_of_mode(GROUP_READABLE | GROUP_WRITE_FILE)
    };
    apply_attributes(&fs::File::open(&file)?, &stamp, OTHER_UID)?;
    let after = fs::metadata(&file)?;
    assert_eq!(after.mode() & PERMISSION_BITS, GROUP_READABLE);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    Ok(())
}


#[test]
fn a_closed_output_is_an_error_after_the_file_was_sealed() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let name = file.display().to_string();
    let outcome = seal_with(&words(&[&name]), &mut FailingOutput, |_path| Ok(()), current_uid());
    assert!(matches!(outcome, Err(SealError::Io(_))));
    Ok(())
}


#[test]
fn the_production_entry_seals_with_the_effective_user() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let mut out = Vec::new();
    seal_tags(&words(&[&file.display().to_string()]), &mut out)?;
    assert_eq!(String::from_utf8(out)?, "sealed: 2 tags sealed\n");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_dispatches_the_seal_command_and_still_refuses_other_shapes() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    run(&words(&["seal-tags", &file.display().to_string()])).await?;
    assert_eq!(fs::read_to_string(&file)?, sealed_text(BODY));
    let refused = run(&words(&["seal-tags"])).await.err().ok_or("expected a usage error")?;
    assert!(refused.to_string().contains("seal-tags [--reseal]"));
    Ok(())
}


#[test]
fn the_binary_seals_prints_the_count_and_refuses_a_second_seal() -> TestResult {
    let dir = tempdir()?;
    let file = put(dir.path(), "tags.yaml", BODY, OWNER_ONLY)?;
    let first = Command::new(PROGRAM).arg("seal-tags").arg(&file).output()?;
    assert!(first.status.success());
    assert_eq!(String::from_utf8(first.stdout)?, "sealed: 2 tags sealed\n");
    let second = Command::new(PROGRAM).arg("seal-tags").arg(&file).output()?;
    assert!(!second.status.success());
    assert!(String::from_utf8(second.stderr)?.contains("--reseal"));
    let reseal = Command::new(PROGRAM).args(["seal-tags", "--reseal"]).arg(&file).output()?;
    assert_eq!(String::from_utf8(reseal.stdout)?, "unchanged\n");
    Ok(())
}
