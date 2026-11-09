use crate::support::{exclusion, hash, image, probe, reasons_for, BPF_AGENT_INDEX, HASH_PAIRS};
use crate::types::TestResult;
use policy_validator::model::{ObservedImage, PathForm, Reason, Scope, SelectorKind};
use std::error::Error;


const OTHER_HASH: &str = "cd";


fn with_images(scope: Scope, kind: SelectorKind, value: &str, images: Vec<ObservedImage>) -> Result<Vec<Reason>, Box<dyn Error>> {
    let mut proposal = exclusion(scope, kind, value);
    proposal.evidence.observed_images = images;
    reasons_for(proposal)
}


fn at(path: &str, name: &str) -> ObservedImage {
    ObservedImage {
        path: path.to_owned(),
        ..image(name)
    }
}


fn unbound() -> Vec<Reason> {
    vec![Reason::SelectorNotInEvidence]
}


#[test]
fn c3_finding_1_a_hash_must_equal_an_observed_sha256() -> TestResult {
    let other = OTHER_HASH.repeat(HASH_PAIRS);
    for scope in [Scope::Global, Scope::EndpointGroup, Scope::SingleEndpoint] {
        let mut proposal = exclusion(scope, SelectorKind::Hash, &other);
        proposal.evidence.observed_images = vec![image("tool")];
        assert_eq!(reasons_for(proposal)?, unbound(), "{scope:?}");
    }
    Ok(())
}


#[test]
fn c3_finding_1_a_hash_must_equal_the_known_hash_when_present() -> TestResult {
    let mut proposal = exclusion(Scope::Global, SelectorKind::Hash, &hash());
    proposal.evidence.known_hash = Some(OTHER_HASH.repeat(HASH_PAIRS));
    assert_eq!(reasons_for(proposal)?, unbound());
    let mut same = exclusion(Scope::Global, SelectorKind::Hash, &hash().to_uppercase());
    same.evidence.known_hash = Some(hash());
    assert_eq!(reasons_for(same)?, vec![]);
    Ok(())
}


#[test]
fn c3_finding_2_a_path_must_cover_every_observed_image() -> TestResult {
    for value in ["/var/www/uploads/x", "/var/www/html/upload.php"] {
        assert_eq!(
            with_images(Scope::SingleEndpoint, SelectorKind::Path, value, vec![image("tool")])?,
            unbound(),
            "{value}"
        );
    }
    let directory = with_images(
        Scope::SingleEndpoint,
        SelectorKind::Path,
        "/srv/app",
        vec![image("tool"), at("/srv/app/lib/helper", "helper")],
    )?;
    assert_eq!(directory, vec![Reason::DirectorySelector]);
    let escaping = with_images(
        Scope::SingleEndpoint,
        SelectorKind::Path,
        "/srv/app/bin",
        vec![image("tool"), at("/srv/other/helper", "helper")],
    )?;
    assert_eq!(escaping, vec![Reason::DirectorySelector]);
    let wrong_flavour = with_images(
        Scope::SingleEndpoint,
        SelectorKind::Path,
        "/srv/app/bin/tool",
        vec![at(r"C:\srv\app\bin\tool", "tool")],
    )?;
    assert_eq!(wrong_flavour, unbound());
    let bad_image_path = with_images(
        Scope::SingleEndpoint,
        SelectorKind::Path,
        "/srv/app/bin/tool",
        vec![at("relative/tool", "tool")],
    )?;
    assert_eq!(bad_image_path, unbound());
    Ok(())
}


#[test]
fn c3_finding_2_a_process_name_and_a_command_line_executable_must_be_observed() -> TestResult {
    assert_eq!(
        with_images(
            Scope::SingleEndpoint,
            SelectorKind::ProcessName,
            "/srv/app/bin/other",
            vec![image("tool")]
        )?,
        unbound()
    );
    assert_eq!(
        with_images(
            Scope::SingleEndpoint,
            SelectorKind::CommandLine,
            "/srv/app/bin/other --x",
            vec![image("tool")]
        )?,
        unbound()
    );
    assert_eq!(
        with_images(
            Scope::SingleEndpoint,
            SelectorKind::CommandLine,
            "/srv/app/bin/tool --x",
            vec![image("tool")]
        )?,
        vec![]
    );
    Ok(())
}


#[test]
fn c3_finding_3_interpreters_and_os_binaries_are_refused_by_path_at_one_endpoint() -> TestResult {
    let powershell_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let powershell = ObservedImage {
        os_component: true,
        original_file_name: Some("PowerShell.EXE".to_owned()),
        ..at(powershell_path, "powershell.exe")
    };
    let by_path = with_images(Scope::SingleEndpoint, SelectorKind::Path, powershell_path, vec![powershell])?;
    assert!(by_path.contains(&Reason::SystemBinary {
        name: "powershell.exe".to_owned()
    }));
    for (path, name) in [
        (r"C:\Windows\System32\cmd.exe", "cmd.exe"),
        ("/usr/bin/python3", "python3"),
        ("/usr/bin/awk", "awk"),
    ] {
        let os = ObservedImage {
            os_component: true,
            ..at(path, name)
        };
        let listed = with_images(Scope::SingleEndpoint, SelectorKind::Path, path, vec![os])?;
        assert!(listed.contains(&Reason::SystemBinary { name: name.to_owned() }), "{path}");
    }
    let rundll_path = r"C:\Windows\System32\rundll32.exe";
    let rundll = ObservedImage {
        os_component: true,
        ..at(rundll_path, "rundll32.exe")
    };
    let by_name = with_images(Scope::SingleEndpoint, SelectorKind::ProcessName, rundll_path, vec![rundll])?;
    assert!(by_name.contains(&Reason::SystemBinary {
        name: "rundll32.exe".to_owned()
    }));
    Ok(())
}


#[test]
fn c3_finding_3_os_directories_are_refused_unless_the_selector_is_an_image_path() -> TestResult {
    for (directory, image_path) in [
        (
            r"C:\Windows\System32\WindowsPowerShell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\x.exe",
        ),
        (r"C:\Windows\Microsoft.NET", r"C:\Windows\Microsoft.NET\Framework\x.exe"),
        ("/usr/lib", "/usr/lib/app/x"),
    ] {
        let found = with_images(Scope::SingleEndpoint, SelectorKind::Path, directory, vec![at(image_path, "x")])?;
        assert!(
            found.iter().any(|reason| matches!(reason, Reason::OsDirectory { .. })),
            "{directory}: {found:?}"
        );
    }
    let exact = with_images(
        Scope::SingleEndpoint,
        SelectorKind::Path,
        "/usr/local/bin/app",
        vec![at("/usr/local/bin/app", "app")],
    )?;
    assert_eq!(exact, vec![]);
    Ok(())
}


#[test]
fn c3_finding_4_a_command_line_executable_is_bound_and_its_flags_apply() -> TestResult {
    for (line, path, original) in [
        ("/usr/bin/python3-dbg /opt/app/job.py", "/usr/bin/python3-dbg", "python3"),
        ("/usr/bin/pwsh-preview -File /opt/app/x.ps1", "/usr/bin/pwsh-preview", "pwsh"),
    ] {
        let renamed = ObservedImage {
            original_file_name: Some(original.to_owned()),
            ..at(path, "x")
        };
        let found = with_images(Scope::SingleEndpoint, SelectorKind::CommandLine, line, vec![renamed])?;
        assert!(found.contains(&Reason::SystemBinary { name: "x".to_owned() }), "{line}: {found:?}");
    }
    let env = ObservedImage {
        os_component: true,
        ..at("/usr/bin/env", "env")
    };
    let found = with_images(Scope::SingleEndpoint, SelectorKind::CommandLine, "/usr/bin/env bash-static", vec![env])?;
    assert!(found.contains(&Reason::SystemBinary { name: "env".to_owned() }));
    Ok(())
}


#[test]
fn c3_finding_4_tokens_are_stripped_of_punctuation_before_the_name_check() -> TestResult {
    let found = with_images(
        Scope::SingleEndpoint,
        SelectorKind::CommandLine,
        "/srv/app/bin/tool --headless ,powershell",
        vec![image("tool")],
    )?;
    assert_eq!(
        found,
        vec![Reason::InterpreterInCommandLine {
            name: "powershell".to_owned()
        }]
    );
    Ok(())
}


#[test]
fn c3_finding_6_second_net_aliases_and_sensor_tampering() -> TestResult {
    for value in [
        "/var/run/lock/x",
        r"C:\Windows\System32\FxsTmp\x.exe",
        r"C:\Windows\System32\Tasks_Migrated\x",
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert!(
            found.iter().any(|reason| matches!(reason, Reason::UserWritableDirectory { .. })),
            "{value}: {found:?}"
        );
    }
    let found = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/usr/sbin/bpftool prog detach id 42")?;
    assert_eq!(found, vec![Reason::ServiceControlInCommandLine { name: "bpftool".to_owned() }]);
    let removal = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/usr/bin/rm -rf /sys/fs/bpf")?;
    assert_eq!(
        removal,
        vec![Reason::ProtectedPath {
            list: "agent_paths".to_owned(),
            index: BPF_AGENT_INDEX
        }]
    );
    let by_path = probe(Scope::SingleEndpoint, SelectorKind::Path, "/usr/sbin/bpftool")?;
    assert!(by_path.contains(&Reason::ServiceControlInCommandLine { name: "bpftool".to_owned() }));
    Ok(())
}


#[test]
fn c3_living_off_the_land_names_are_refused_even_without_the_platform_flag() -> TestResult {
    for name in ["certutil.exe", "wmic.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "msbuild.exe"] {
        for scope in [Scope::Global, Scope::EndpointGroup] {
            let found = with_images(scope, SelectorKind::Hash, &hash(), vec![image(name)])?;
            assert_eq!(found, vec![Reason::SystemBinary { name: name.to_owned() }], "{name}");
        }
    }
    Ok(())
}


#[test]
fn c3_a_non_canonical_selector_gets_no_binding_reason() -> TestResult {
    let found = probe(Scope::SingleEndpoint, SelectorKind::ProcessName, "tool")?;
    assert_eq!(found, vec![Reason::NonCanonical { form: PathForm::NotAbsolute }]);
    let empty = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "")?;
    assert!(empty.contains(&Reason::NonCanonical { form: PathForm::Empty }));
    assert!(!empty.contains(&Reason::SelectorNotInEvidence));
    Ok(())
}


const PROGRAM_IMAGE: &str = r"C:\Program Files\Vendor\app.exe";


fn refused_against(kind: SelectorKind, value: &str, image_path: &str) -> Result<Vec<Reason>, Box<dyn Error>> {
    with_images(Scope::SingleEndpoint, kind, value, vec![at(image_path, "app.exe")])
}


#[test]
fn t043d_a_path_selector_must_equal_an_image_path_drive_included() -> TestResult {
    for (kind, value) in [
        (SelectorKind::Path, r"E:\Program Files\Vendor\app.exe"),
        (SelectorKind::ProcessName, r"D:\Program Files\Vendor\app.exe"),
        (SelectorKind::Path, r"C:\Program Files\Vendor\other.exe"),
    ] {
        assert_eq!(refused_against(kind, value, PROGRAM_IMAGE)?, unbound(), "{value}");
    }
    assert_eq!(refused_against(SelectorKind::Path, PROGRAM_IMAGE, PROGRAM_IMAGE)?, vec![]);
    Ok(())
}


#[test]
fn t043d_a_directory_selector_is_refused() -> TestResult {
    for (value, image_path) in [
        (r"D:\Program Files\Vendor", r"D:\Program Files\Vendor\app.exe"),
        ("/var/www", "/var/www/html/app"),
        ("/srv", "/srv/app/bin/tool"),
        (r"C:\Program Files (x86)", r"C:\Program Files (x86)\V\app.exe"),
    ] {
        let found = refused_against(SelectorKind::Path, value, image_path)?;
        assert!(found.contains(&Reason::DirectorySelector), "{value}: {found:?}");
        assert!(!found.contains(&Reason::SelectorNotInEvidence), "{value}: {found:?}");
    }
    Ok(())
}


#[test]
fn t043d_case_rules_follow_the_operating_system() -> TestResult {
    assert_eq!(
        refused_against(SelectorKind::Path, r"C:\PROGRAM FILES\Vendor\app.exe", PROGRAM_IMAGE)?,
        vec![]
    );
    assert_eq!(
        refused_against(SelectorKind::Path, r"c:\program files\vendor\APP.EXE", PROGRAM_IMAGE)?,
        vec![]
    );
    assert_eq!(refused_against(SelectorKind::Path, "/srv/APP/bin/tool", "/srv/app/bin/tool")?, unbound());
    Ok(())
}


#[test]
fn t043d_a_command_line_under_program_files_binds_to_the_image() -> TestResult {
    for value in [r#""C:\Program Files\Vendor\app.exe" --run"#, r#""C:\PROGRAM FILES\Vendor\app.exe""#] {
        assert_eq!(refused_against(SelectorKind::CommandLine, value, PROGRAM_IMAGE)?, vec![], "{value}");
    }
    for value in [
        r#""C:\Program Files\Vendor\app.exe.bak" --run"#,
        r#""C:\Program Files\Vendor\other.exe" --run"#,
        r#""E:\Program Files\Vendor\app.exe" --run"#,
        r#""C:\Program Files\Vendor\app.exe x\evil.exe""#,
        r#""C:\Program Files\Vendor\app.exe helper\run.exe" --serve"#,
    ] {
        assert_eq!(refused_against(SelectorKind::CommandLine, value, PROGRAM_IMAGE)?, unbound(), "{value}");
    }
    for value in [
        r"C:\Program Files\Vendor\app.exe x\evil.exe",
        r"C:\Program Files\Vendor\app.exe",
        r"C:\Program Files\Vendor\app.exe -o\Users\Public\drop.dll",
        r#""C:\Program Files\Vendor\app.exe" -o\Users\Public\drop.dll"#,
        r#""C:\Program Files\Vendor\app.exe" C:\Users\Public\drop.dll"#,
    ] {
        let found = refused_against(SelectorKind::CommandLine, value, PROGRAM_IMAGE)?;
        assert!(!found.is_empty(), "{value}");
    }
    assert_eq!(
        refused_against(SelectorKind::CommandLine, "/srv/APP/bin/tool x", "/srv/app/bin/tool")?,
        unbound()
    );
    Ok(())
}
