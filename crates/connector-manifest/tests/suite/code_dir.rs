use crate::common::types::Failure;
use crate::common::types::TestResult;
use crate::support::{elf_with_types, fixture, gate_name, generated_name, leftovers, python_fixture, runner_uid, tiny_elf, PT_INTERP, PT_LOAD};
use connector_manifest::code_dir::{copy_package, create_code_dir, write_code_file, ENTRY_MODE, FILE_MODE, GATE_SCRIPT};
use connector_manifest::error::ConnectorError;
use connector_manifest::model::MANIFEST_NAME;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};


const MODE_MASK: u32 = 0o777;


const WORLD_WRITABLE: u32 = 0o777;


const FIXED_NAME: &str = "fixed-name";


fn fixed_name() -> io::Result<String> {
    Ok(FIXED_NAME.to_owned())
}


fn failing_name() -> io::Result<String> {
    Err(io::Error::other("injected namer failure"))
}


fn mode_of(path: &std::path::Path) -> Result<u32, Failure> {
    Ok(fs::metadata(path)?.permissions().mode() & MODE_MASK)
}


#[test]
fn every_signed_file_is_copied_with_its_mode_and_the_gate_and_all_of_it_vanishes_on_drop() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    let code = copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    )?;
    assert_eq!(fs::read(code.path.join("main.py"))?, b"print(1)");
    assert_eq!(
        fs::read(code.path.join(MANIFEST_NAME))?,
        fs::read(fixture.package.path().join(MANIFEST_NAME))?
    );
    assert_eq!(fs::read_to_string(code.path.join(gate_name()))?, GATE_SCRIPT);
    assert_eq!(mode_of(&code.path.join("main.py"))?, ENTRY_MODE);
    assert_eq!(mode_of(&code.path.join(MANIFEST_NAME))?, FILE_MODE);
    assert_eq!(mode_of(&code.path.join(gate_name()))?, FILE_MODE);
    assert_eq!(leftovers(fixture.code_root.path())?, 1);
    drop(code);
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    Ok(())
}


#[test]
fn a_file_rewritten_in_place_after_verification_is_refused_and_nothing_is_left() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    let mut file = OpenOptions::new().write(true).open(fixture.package.path().join("main.py"))?;
    file.write_all(b"print(2)")?;
    let verdict = copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(verdict, Err(ConnectorError::FileChanged { path }) if path == "main.py"));
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    fs::write(fixture.package.path().join("main.py"), b"print(1) # longer")?;
    let longer = copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(longer, Err(ConnectorError::FileChanged { .. })));
    Ok(())
}


#[test]
fn a_symlink_a_missing_file_and_a_missing_package_are_refused() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    fs::remove_file(fixture.package.path().join("main.py"))?;
    symlink("/etc/passwd", fixture.package.path().join("main.py"))?;
    let linked = copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(linked, Err(ConnectorError::Symlink { .. })));
    fs::remove_file(fixture.package.path().join("main.py"))?;
    let gone = copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(gone, Err(ConnectorError::Io { .. })));
    let absent = fixture.package.path().join("absent");
    let missing = copy_package(&fixture.verified, &absent, fixture.code_root.path(), runner_uid(), generated_name);
    assert!(matches!(missing, Err(ConnectorError::Io { .. })));
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    Ok(())
}


#[test]
fn an_entry_that_is_not_in_the_signed_list_is_refused() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    let mut verified = fixture.verified.clone();
    verified.files.remove("main.py");
    let verdict = copy_package(&verified, fixture.package.path(), fixture.code_root.path(), runner_uid(), generated_name);
    assert!(matches!(verdict, Err(ConnectorError::MissingEntry)));
    Ok(())
}


#[test]
fn a_native_entry_must_be_a_static_elf_judged_on_the_copied_bytes() -> TestResult {
    let script = fixture("connector", "native", b"#!/tmp/x\nexit 0\n")?;
    let refused = copy_package(
        &script.verified,
        script.package.path(),
        script.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(refused, Err(ConnectorError::UnsupportedEntry { .. })));
    assert_eq!(leftovers(script.code_root.path())?, 0);
    let dynamic = fixture("connector", "native", &elf_with_types(&[PT_LOAD, PT_INTERP]))?;
    let loader = copy_package(
        &dynamic.verified,
        dynamic.package.path(),
        dynamic.code_root.path(),
        runner_uid(),
        generated_name,
    );
    assert!(matches!(loader, Err(ConnectorError::UnsupportedEntry { .. })));
    let fine = fixture("connector", "native", &tiny_elf(b"{}"))?;
    let code = copy_package(&fine.verified, fine.package.path(), fine.code_root.path(), runner_uid(), generated_name)?;
    assert_eq!(mode_of(&code.path.join("connector"))?, ENTRY_MODE);
    Ok(())
}


#[test]
fn a_python_entry_is_not_judged_as_an_elf() -> TestResult {
    let fixture = fixture("main.py", "python3", b"#!/usr/bin/env python3\nprint(1)\n")?;
    copy_package(
        &fixture.verified,
        fixture.package.path(),
        fixture.code_root.path(),
        runner_uid(),
        generated_name,
    )?;
    Ok(())
}


#[test]
fn a_failing_namer_an_existing_name_and_an_unsafe_root_are_refused() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    let failed = create_code_dir(fixture.code_root.path(), runner_uid(), failing_name);
    assert!(matches!(failed, Err(ConnectorError::Io { .. })));
    let first = create_code_dir(fixture.code_root.path(), runner_uid(), fixed_name)?;
    let second = create_code_dir(fixture.code_root.path(), runner_uid(), fixed_name);
    assert!(matches!(second, Err(ConnectorError::Io { .. })));
    drop(first);
    fs::set_permissions(fixture.code_root.path(), fs::Permissions::from_mode(WORLD_WRITABLE))?;
    let open = create_code_dir(fixture.code_root.path(), runner_uid(), generated_name);
    assert!(matches!(open, Err(ConnectorError::WorkDir(_))));
    Ok(())
}


#[test]
fn a_file_name_that_exists_is_never_overwritten_or_followed() -> TestResult {
    let fixture = python_fixture("print(1)")?;
    let mut code = create_code_dir(fixture.code_root.path(), runner_uid(), generated_name)?;
    write_code_file(&mut code, "a", b"1", FILE_MODE)?;
    assert!(write_code_file(&mut code, "a", b"2", FILE_MODE).is_err());
    assert_eq!(fs::read(code.path.join("a"))?, b"1");
    Ok(())
}


#[test]
fn the_gate_script_exits_on_eof_instead_of_starting_the_connector() -> TestResult {
    let directory = tempfile::tempdir()?;
    let script = directory.path().join("gate.sh");
    fs::write(&script, GATE_SCRIPT)?;
    let output = std::process::Command::new("/bin/sh")
        .arg(&script)
        .args(["/bin/echo", "started"])
        .stdin(std::process::Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}
