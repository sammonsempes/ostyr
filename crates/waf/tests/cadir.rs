#![cfg(unix)]

use data_encoding::HEXLOWER;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use waf::cadir::{ca_root_path, directory_trusted, remove_temporary, store_in, write_ca_root};
use waf::cli::{place_ca_root, render_to};
use waf::error::WafError;
use waf::model::CaRoot;
use waf::render::render_text;
use waf::tls::check_ca_root;


const CA_PEM: &str = "tests/fixtures/ca.pem";


const DIRECTORY: &str = "https://acme.example.test/directory";


const EMAIL: &str = "ops@example.test";


const FILE_MODE: u32 = 0o644;


const GROUP_WRITABLE: u32 = 0o775;


const OWNER_ONLY: u32 = 0o700;


const SAFE_DIRECTORY_MODE: u32 = 0o755;


const FOREIGN_USER: u32 = 4_242;


const OTHER_FOREIGN_USER: u32 = 4_243;


const MODE_BITS: u32 = 0o777;


const INVALID_NAME_BYTES: [u8; 2] = [0xff, 0xfe];


fn routes_yaml(root_file: &Path) -> String {
    json!({
        "tls": {"issuer": "acme", "directory": DIRECTORY, "email": EMAIL, "ca_root_file": root_file.to_string_lossy()},
        "routes": [{"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]}]
    })
    .to_string()
}


fn sample_root() -> Result<CaRoot, Box<dyn Error>> {
    Ok(CaRoot {
        name: "ca-root-sample.pem".to_string(),
        pem: fs::read_to_string(CA_PEM)?,
    })
}


#[test]
fn the_written_file_holds_exactly_the_checked_bytes() -> Result<(), Box<dyn Error>> {
    let work = tempfile::tempdir()?;
    let out = tempfile::tempdir()?;
    let operator = work.path().join("root.pem");
    fs::copy(CA_PEM, &operator)?;
    let root = check_ca_root(&operator.to_string_lossy())?;
    let other = format!("{0}{0}", fs::read_to_string(CA_PEM)?);
    fs::write(&operator, &other)?;
    write_ca_root(out.path(), &root)?;
    let written = fs::read_to_string(out.path().join(&root.name))?;
    assert_eq!(written, fs::read_to_string(CA_PEM)?);
    assert_ne!(written, other);
    assert_eq!(root.name, format!("ca-root-{}.pem", HEXLOWER.encode(&Sha256::digest(written.as_bytes()))));
    assert_eq!(fs::metadata(out.path().join(&root.name))?.permissions().mode() & MODE_BITS, FILE_MODE);
    let again = write_ca_root(out.path(), &root);
    assert!(again.is_ok());
    assert_eq!(fs::read_dir(out.path())?.count(), 1);
    Ok(())
}


#[test]
fn the_rendered_path_is_the_written_file_not_the_operator_path() -> Result<(), Box<dyn Error>> {
    let work = tempfile::tempdir()?;
    let out = tempfile::tempdir()?;
    let operator = work.path().join("root.pem");
    fs::copy(CA_PEM, &operator)?;
    let mut json_out = Vec::new();
    let refused = render_to(&mut routes_yaml(&operator).as_bytes(), &mut json_out, &mut Vec::new(), out.path())?;
    assert_eq!(refused, 0);
    let value: Value = serde_json::from_slice(&json_out)?;
    let listed = value
        .pointer("/apps/tls/automation/policies/0/issuers/0/trusted_roots_pem_files/0")
        .and_then(Value::as_str);
    let name = format!("ca-root-{}.pem", HEXLOWER.encode(&Sha256::digest(fs::read(CA_PEM)?)));
    let expected = out.path().join(name);
    assert_eq!(listed.map(Path::new), Some(expected.as_path()));
    assert_ne!(listed, operator.to_str());
    assert_eq!(fs::read(&expected)?, fs::read(CA_PEM)?);
    Ok(())
}


#[test]
fn an_untrusted_directory_is_refused_before_any_write() -> Result<(), Box<dyn Error>> {
    let work = tempfile::tempdir()?;
    let operator = work.path().join("root.pem");
    fs::copy(CA_PEM, &operator)?;
    let open_directory = tempfile::tempdir()?;
    fs::set_permissions(open_directory.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    let target = tempfile::tempdir()?;
    let link = work.path().join("link");
    symlink(target.path(), &link)?;
    let relative = Path::new("tests");
    [open_directory.path(), relative, link.as_path()].iter().for_each(|directory| {
        let result = render_to(&mut routes_yaml(&operator).as_bytes(), &mut Vec::new(), &mut Vec::new(), directory);
        assert!(matches!(result, Err(WafError::BadCaDir(_) | WafError::CaWrite(_))), "{directory:?}");
    });
    assert!(matches!(
        render_to(
            &mut routes_yaml(&operator).as_bytes(),
            &mut Vec::new(),
            &mut Vec::new(),
            open_directory.path()
        ),
        Err(WafError::BadCaDir(_))
    ));
    assert!(matches!(
        render_to(&mut routes_yaml(&operator).as_bytes(), &mut Vec::new(), &mut Vec::new(), relative),
        Err(WafError::BadCaDir(_))
    ));
    assert!(matches!(
        render_to(&mut routes_yaml(&operator).as_bytes(), &mut Vec::new(), &mut Vec::new(), &link),
        Err(WafError::CaWrite(_))
    ));
    assert_eq!(fs::read_dir(open_directory.path())?.count(), 0);
    assert_eq!(fs::read_dir(target.path())?.count(), 0);
    Ok(())
}


#[test]
fn directory_ownership_and_mode_are_judged() -> Result<(), Box<dyn Error>> {
    assert!(directory_trusted(SAFE_DIRECTORY_MODE, FOREIGN_USER, FOREIGN_USER));
    assert!(directory_trusted(OWNER_ONLY, 0, FOREIGN_USER));
    assert!(!directory_trusted(OWNER_ONLY, OTHER_FOREIGN_USER, FOREIGN_USER));
    assert!(!directory_trusted(GROUP_WRITABLE, FOREIGN_USER, FOREIGN_USER));
    Ok(())
}


#[test]
fn a_failed_rename_removes_the_temporary_file() -> Result<(), Box<dyn Error>> {
    let out = tempfile::tempdir()?;
    let root = sample_root()?;
    fs::create_dir(out.path().join(&root.name))?;
    let result = write_ca_root(out.path(), &root);
    assert!(matches!(result, Err(WafError::CaWrite(_))));
    let names: Vec<_> = fs::read_dir(out.path())?
        .map(|entry| entry.map(|found| found.file_name()))
        .collect::<Result<_, _>>()?;
    assert_eq!(names, [root.name.as_str()]);
    Ok(())
}


#[test]
fn an_unwritable_temporary_name_and_a_missing_temporary_are_errors() -> Result<(), Box<dyn Error>> {
    let out = tempfile::tempdir()?;
    let handle = fs::File::open(out.path())?;
    let owned = std::os::fd::OwnedFd::from(handle);
    let result = store_in(&owned, "missing/dir/file", "name.pem", b"x");
    assert!(matches!(result, Err(WafError::CaWrite(_))));
    remove_temporary(&owned, "never-created");
    Ok(())
}


#[test]
fn a_path_that_is_not_utf8_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = Path::new(OsStr::from_bytes(&INVALID_NAME_BYTES));
    assert!(matches!(ca_root_path(directory, &sample_root()?), Err(WafError::BadCaDir(_))));
    Ok(())
}


#[test]
fn only_issuers_that_trust_a_private_root_are_placed() -> Result<(), Box<dyn Error>> {
    let operator = tempfile::tempdir()?.path().join("root.pem");
    fs::create_dir_all(operator.parent().ok_or("no parent")?)?;
    fs::copy(CA_PEM, &operator)?;
    let mut rendered = render_text(&routes_yaml(&operator))?;
    place_ca_root(&mut rendered.config, Some("/etc/x.pem"));
    let value = serde_json::to_value(&rendered.config)?;
    assert_eq!(
        value.pointer("/apps/tls/automation/policies/0/issuers/0/trusted_roots_pem_files/0"),
        Some(&json!("/etc/x.pem"))
    );
    place_ca_root(&mut rendered.config, None);
    let cleared = serde_json::to_value(&rendered.config)?;
    assert_eq!(cleared.pointer("/apps/tls/automation/policies/0/issuers/0/trusted_roots_pem_files"), None);
    let mut internal =
        render_text(&json!({"tls": {"issuer": "internal"}, "routes": [{"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]}]}).to_string())?;
    place_ca_root(&mut internal.config, Some("/etc/x.pem"));
    assert!(internal.ca_root.is_none());
    assert!(!serde_json::to_string(&internal.config)?.contains("/etc/x.pem"));
    Ok(())
}
