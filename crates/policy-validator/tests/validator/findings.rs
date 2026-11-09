use crate::support::{bench, exclusion, hash, image, loaded, probe, reasons_for, validation_context};
use crate::types::TestResult;
use policy_validator::audit::validate_audited;
use policy_validator::model::{ObservedImage, PathForm, Proposal, Reason, Scope, SelectorKind};
use policy_validator::rules::{validate, wide_scope_reason};
use std::error::Error;
use std::fs;


const SECRET_ENTRIES: [&str; 3] = ["canary-9", "edrsecret", "agent-7"];


const SENSITIVE_POLICY: &str = "honeytoken_paths: [/srv/canary-9]\nsecurity_sensors: [edrsecret]\nagent_paths: [/opt/agent-7]\n";


#[test]
fn t043g_verdicts_and_audit_name_the_list_and_index_never_the_entry() -> TestResult {
    let bench = bench(SENSITIVE_POLICY)?;
    let context = validation_context();
    for (kind, value, expected) in [
        (SelectorKind::Path, "/srv/canary-9/secret.db", "honeytoken_paths[0]"),
        (SelectorKind::Path, "/srv", "honeytoken_paths[0]"),
        (SelectorKind::Path, "/opt/agent-7", "agent_paths[0]"),
        (SelectorKind::Path, "/opt", "agent_paths[0]"),
        (SelectorKind::CommandLine, "/srv/app/tool edrsecret", "security_sensors[0]"),
    ] {
        let proposal = Proposal::Exclusion(exclusion(Scope::SingleEndpoint, kind, value));
        let verdict = validate_audited(&bench.engine, &context, &proposal)?;
        let shown: Vec<String> = verdict.reasons.iter().map(ToString::to_string).collect();
        assert!(shown.iter().any(|reason| reason.contains(expected)), "{value}: {shown:?}");
        let debug = format!("{shown:?}");
        assert!(SECRET_ENTRIES.iter().all(|entry| !debug.contains(entry)), "{value}: {debug}");
    }
    let audit = fs::read_to_string(&bench.audit_file)?;
    assert!(
        audit.contains("honeytoken_paths[0]") && audit.contains("agent_paths[0]") && audit.contains("security_sensors[0]"),
        "{audit}"
    );
    assert!(SECRET_ENTRIES.iter().all(|entry| !audit.contains(entry)), "{audit}");
    Ok(())
}


#[test]
fn t043g_cycle_2_an_observed_image_matching_a_sensor_entry_names_only_the_index() -> TestResult {
    let bench = bench(SENSITIVE_POLICY)?;
    let context = validation_context();
    let named = ObservedImage {
        name: "edrsecret.exe".to_owned(),
        path: "/srv/app/bin/plain".to_owned(),
        ..image("plain")
    };
    let renamed = ObservedImage {
        original_file_name: Some("EDRSECRET.EXE".to_owned()),
        ..image("plain")
    };
    for observed in [named, renamed] {
        for (os_component, writable_by_non_admin) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut selected = exclusion(Scope::Global, SelectorKind::Hash, &hash());
            selected.evidence.observed_images = vec![ObservedImage {
                os_component,
                writable_by_non_admin,
                ..observed.clone()
            }];
            let verdict = validate_audited(&bench.engine, &context, &Proposal::Exclusion(selected))?;
            assert_eq!(verdict.reasons, vec![Reason::ListedSecuritySensor { index: 0 }]);
        }
    }
    let audit = fs::read_to_string(&bench.audit_file)?;
    assert!(
        audit.contains("security_sensors[0]") && !audit.to_lowercase().contains("edrsecret"),
        "{audit}"
    );
    Ok(())
}


fn wide_refused(kind: SelectorKind, value: &str) -> Result<(), Box<dyn Error>> {
    for scope in [Scope::Global, Scope::EndpointGroup] {
        assert_eq!(probe(scope, kind, value)?, vec![wide_scope_reason(kind)], "{scope:?} {kind:?} {value}");
    }
    Ok(())
}


fn endpoint_form(kind: SelectorKind, value: &str, form: PathForm) -> Result<(), Box<dyn Error>> {
    let found = probe(Scope::SingleEndpoint, kind, value)?;
    assert!(found.contains(&Reason::NonCanonical { form }), "{kind:?} {value}: {found:?}");
    Ok(())
}


fn endpoint_writable(kind: SelectorKind, value: &str, directory: &str) -> Result<(), Box<dyn Error>> {
    let found = probe(Scope::SingleEndpoint, kind, value)?;
    assert!(
        found.contains(&Reason::UserWritableDirectory {
            directory: directory.to_owned()
        }),
        "{value}: {found:?}"
    );
    Ok(())
}


fn global_image_refused(name: &str) -> Result<(), Box<dyn Error>> {
    let mut proposal = exclusion(Scope::Global, SelectorKind::Hash, &hash());
    proposal.evidence.observed_images = vec![image(name)];
    assert_eq!(reasons_for(proposal)?, vec![Reason::SystemBinary { name: name.to_owned() }], "{name}");
    Ok(())
}


#[test]
fn t043_c1_finding_1_variables_tilde_and_driveless_forms() -> TestResult {
    for (value, form) in [
        (r"%USERPROFILE%\evil.exe", PathForm::NotAbsolute),
        (r"%WINDIR%\Temp\x.exe", PathForm::NotAbsolute),
        (r"\Users\bob\evil.exe", PathForm::NotAbsolute),
        ("~/x", PathForm::Tilde),
    ] {
        wide_refused(SelectorKind::Path, value)?;
        endpoint_form(SelectorKind::Path, value, form)?;
    }
    Ok(())
}


#[test]
fn t043_c1_finding_2_wildcards() -> TestResult {
    for (kind, value, form) in [
        (SelectorKind::Path, r"C:\Windows\System32\*.exe", PathForm::Wildcard),
        (SelectorKind::Path, r"C:\U*\bob\evil.exe", PathForm::Wildcard),
        (SelectorKind::ProcessName, "*", PathForm::NotAbsolute),
    ] {
        wide_refused(kind, value)?;
        endpoint_form(kind, value, form)?;
    }
    Ok(())
}


#[test]
fn t043_c1_finding_3_process_name_and_command_line_get_the_path_rules() -> TestResult {
    wide_refused(SelectorKind::ProcessName, "/tmp/evil")?;
    wide_refused(SelectorKind::ProcessName, r"C:\Program Files\Ostyr\x.exe")?;
    wide_refused(SelectorKind::CommandLine, "/tmp/evil")?;
    endpoint_writable(SelectorKind::ProcessName, "/tmp/evil", "/tmp")?;
    endpoint_writable(SelectorKind::CommandLine, "/tmp/evil", "/tmp")?;
    let protected = probe(Scope::SingleEndpoint, SelectorKind::ProcessName, r"C:\Program Files\Ostyr\x.exe")?;
    assert_eq!(
        protected,
        vec![Reason::ProtectedPath {
            list: "agent_paths".to_owned(),
            index: 0
        }]
    );
    Ok(())
}


#[test]
fn t043_c1_finding_4_a_global_signer_is_refused() -> TestResult {
    wide_refused(SelectorKind::Signer, "Microsoft Windows")
}


#[test]
fn t043_c1_finding_5_interpreter_spellings() -> TestResult {
    wide_refused(SelectorKind::ProcessName, "powershell")?;
    wide_refused(SelectorKind::ProcessName, "/usr/bin/python3.11")?;
    wide_refused(SelectorKind::CommandLine, "/usr/bin/env python3 x.py")?;
    wide_refused(SelectorKind::ProcessName, "POWERS~1.EXE")?;
    endpoint_form(SelectorKind::ProcessName, "powershell", PathForm::NotAbsolute)?;
    endpoint_form(SelectorKind::ProcessName, r"C:\Windows\POWERS~1.EXE", PathForm::ShortName)?;
    ["powershell", "/usr/bin/python3.11", "POWERS~1.EXE"]
        .iter()
        .try_for_each(|name| global_image_refused(name))
}


#[test]
fn t043_c1_finding_6_unknown_fields_are_refused() -> TestResult {
    let text = r#"{"kind":"asr_change","rule_id":"x","new_state":"block","impact":{"techniques":[],"detections":{}},"extra":1}"#;
    assert!(serde_json::from_str::<Proposal>(text).is_err());
    Ok(())
}


#[test]
fn t043_c2_finding_1_unquoted_command_line_with_spaces() -> TestResult {
    for value in [
        r"C:\Program Files\PowerShell\7\pwsh.exe -NoProfile -File x.ps1",
        r"C:\Program Files\Python311\python.exe x.py",
    ] {
        wide_refused(SelectorKind::CommandLine, value)?;
        endpoint_form(SelectorKind::CommandLine, value, PathForm::NotAbsolute)?;
    }
    Ok(())
}


#[test]
fn t043_c2_finding_2_path_glued_to_an_option() -> TestResult {
    for (value, form) in [
        (r"/load:C:\Users\Public\evil.dll", PathForm::AlternateStream),
        (r"-File:C:\Users\Public\x.ps1", PathForm::NotAbsolute),
        ("curl -o/tmp/evil", PathForm::NotAbsolute),
        ("tar -C/tmp", PathForm::NotAbsolute),
        ("--out:/tmp/x", PathForm::NotAbsolute),
    ] {
        wide_refused(SelectorKind::CommandLine, value)?;
        endpoint_form(SelectorKind::CommandLine, value, form)?;
    }
    Ok(())
}


#[test]
fn t043_c2_finding_3_nt_device_paths() -> TestResult {
    for value in [
        r"\Device\HarddiskVolume3\Users\bob\evil.exe",
        r"\Device\HarddiskVolume3\Windows\Temp\x.exe",
        r"\Device\HarddiskVolume3\Program Files\Ostyr\agent.exe",
    ] {
        wide_refused(SelectorKind::Path, value)?;
        endpoint_form(SelectorKind::Path, value, PathForm::NtDevice)?;
    }
    Ok(())
}


#[test]
fn t043_c2_lower_risk_launchers_aliases_places_and_relative_forms() -> TestResult {
    for value in [
        "timeout 5 powershell",
        "nice -n 5 bash",
        "setsid sh",
        "conhost.exe --headless cmd",
        r"forfiles.exe /c cmd",
    ] {
        wide_refused(SelectorKind::CommandLine, value)?;
    }
    ["nodejs", "powershell_ise.exe", "dash", "pythonw.exe"]
        .iter()
        .try_for_each(|name| global_image_refused(name))?;
    for (value, directory) in [
        (r"C:\ProgramData\x.exe", r"C:\ProgramData"),
        (r"C:\Windows\Tasks\x.exe", r"C:\Windows\Tasks"),
        ("/run/user/1000/x", "/run/user"),
        ("/proc/self/root/tmp/x", "/proc"),
        (r"C:\Documents and Settings\bob\x.exe", r"C:\Documents and Settings"),
    ] {
        endpoint_writable(SelectorKind::Path, value, directory)?;
    }
    endpoint_form(SelectorKind::Path, r"C:Users\bob\evil.exe", PathForm::DriveRelative)?;
    endpoint_form(SelectorKind::Path, "bin/tool", PathForm::NotAbsolute)
}


#[test]
fn t043_c3_finding_1_system_binary_directories_at_global_scope() -> TestResult {
    for value in [
        r"C:\Windows\System32",
        r"C:\Windows\System32\WindowsPowerShell",
        r"C:\Program Files\PowerShell\7",
        r"C:\Windows\SysWOW64",
        "/usr/bin",
        "/bin",
        "/usr",
        "/usr/local/bin",
    ] {
        wide_refused(SelectorKind::Path, value)?;
    }
    Ok(())
}


#[test]
fn t043_c3_finding_2_interpreters_glued_to_options_and_operators() -> TestResult {
    for value in ["launcher.exe --run:powershell -enc AAAA", "/c cmd&powershell", "/c x|pwsh"] {
        wide_refused(SelectorKind::CommandLine, value)?;
    }
    Ok(())
}


#[test]
fn t043_c3_finding_3_more_writable_places() -> TestResult {
    for (value, directory) in [
        (
            r"C:\Windows\System32\spool\drivers\color\x.exe",
            r"C:\Windows\System32\spool\drivers\color",
        ),
        (r"C:\Windows\System32\Tasks\x", r"C:\Windows\System32\Tasks"),
        ("/var/lock/x", "/var/lock"),
        ("/run/lock/x", "/run/lock"),
        ("/dev/mqueue/x", "/dev/mqueue"),
    ] {
        endpoint_writable(SelectorKind::Path, value, directory)?;
    }
    Ok(())
}


#[test]
fn t043a_c1_sibling_interpreter_folders() -> TestResult {
    for value in [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319",
        r"C:\Program Files\PowerShell\7-preview",
        r"C:\Program Files\Python311",
        r"C:\Program Files\nodejs",
        "/usr/libexec",
        "/lib32",
        r"C:\Windows\Sysnative",
        r"C:\Windows\System32\wbem",
        "/opt/app/bin",
    ] {
        wide_refused(SelectorKind::Path, value)?;
    }
    Ok(())
}


#[test]
fn t043a_c2_aliases_and_unc_shares() -> TestResult {
    for value in [
        "/var/run/user/1000",
        "/var/run/user/1000/evil",
        "/usr/tmp/evil",
        r"\\server\share\Users\bob\evil.exe",
    ] {
        wide_refused(SelectorKind::Path, value)?;
    }
    endpoint_writable(SelectorKind::Path, "/var/run/user/1000/evil", "/var/run/user")?;
    endpoint_writable(SelectorKind::Path, "/usr/tmp/evil", "/usr/tmp")?;
    endpoint_form(SelectorKind::Path, r"\\server\share\Users\bob\evil.exe", PathForm::Unc)
}


#[test]
fn t043a_c2_process_name_and_command_line_naming_interpreter_folders() -> TestResult {
    for value in [
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0",
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\",
        r"C:\Program Files\nodejs\",
        "/usr/libexec/",
        r"C:\Program Files\Vendor\",
    ] {
        wide_refused(SelectorKind::ProcessName, value)?;
        wide_refused(SelectorKind::CommandLine, value)?;
    }
    endpoint_form(SelectorKind::ProcessName, "/usr/libexec/", PathForm::TrailingSeparator)
}


#[test]
fn t043a_c3_drive_relative_alias_before_dotdot_and_device_unc_forms() -> TestResult {
    for value in [r"C:Windows\SysWOW64\WindowsPowerShell\v1.0\", r"C:Program Files\nodejs\"] {
        wide_refused(SelectorKind::ProcessName, value)?;
        endpoint_form(SelectorKind::ProcessName, value, PathForm::DriveRelative)?;
    }
    for value in ["/var/run/../home/bob/evil", "/var/run/../dev/shm/evil", "/usr/tmp/../crash/evil"] {
        wide_refused(SelectorKind::Path, value)?;
        endpoint_form(SelectorKind::Path, value, PathForm::DotSegment)?;
    }
    for value in [
        r"\Device\Mup\server\share\Users\bob\evil.exe",
        r"\Device\LanmanRedirector\server\share\Users\bob\evil.exe",
        r"\\.\GLOBALROOT\Device\Mup\server\share\Users\bob\evil.exe",
    ] {
        wide_refused(SelectorKind::Path, value)?;
        endpoint_form(SelectorKind::Path, value, PathForm::NtDevice)?;
    }
    Ok(())
}


#[test]
fn t043a_c3_non_blocking_name_only_group_and_directory_arguments() -> TestResult {
    wide_refused(SelectorKind::ProcessName, "tool.exe")?;
    endpoint_form(SelectorKind::CommandLine, "/usr/bin/tool /usr/bin/", PathForm::TrailingSeparator)?;
    let policy = loaded()?;
    let proposal = Proposal::Exclusion(exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash()));
    assert!(validate(&policy, &proposal).reasons.is_empty());
    Ok(())
}
