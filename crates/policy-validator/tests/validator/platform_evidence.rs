use crate::support::{exclusion, hash, image, loaded, probe, reasons_for};
use crate::types::TestResult;
use policy_validator::model::{Evidence, ObservedImage, PathForm, Proposal, Reason, Scope, SelectorKind};
use policy_validator::rules::{validate, MAX_TECHNIQUES, MAX_TECHNIQUE_BYTES};
use std::error::Error;


const WIDE_SCOPES: [Scope; 2] = [Scope::Global, Scope::EndpointGroup];


const ALL_SCOPES: [Scope; 3] = [Scope::Global, Scope::EndpointGroup, Scope::SingleEndpoint];


fn hash_with(scope: Scope, images: Vec<ObservedImage>) -> Result<Vec<Reason>, Box<dyn Error>> {
    let mut proposal = exclusion(scope, SelectorKind::Hash, &hash());
    proposal.evidence.observed_images = images;
    reasons_for(proposal)
}


fn os_image(name: &str) -> ObservedImage {
    ObservedImage {
        os_component: true,
        ..image(name)
    }
}


fn sensor_image(name: &str) -> ObservedImage {
    ObservedImage {
        security_sensor: true,
        ..image(name)
    }
}


fn single_with(kind: SelectorKind, value: &str, images: Vec<ObservedImage>) -> Result<Vec<Reason>, Box<dyn Error>> {
    let mut proposal = exclusion(Scope::SingleEndpoint, kind, value);
    proposal.evidence.observed_images = images;
    reasons_for(proposal)
}


#[test]
fn c2_finding_1_a_system_binary_hash_is_refused_at_global_and_group_scope() -> TestResult {
    for name in [
        "certutil.exe",
        "svchost.exe",
        "csc.exe",
        "/usr/bin/awk",
        "/usr/bin/env",
        "bash-static",
        "pwsh-preview",
        "python3-dbg",
    ] {
        for scope in WIDE_SCOPES {
            assert_eq!(
                hash_with(scope, vec![os_image(name)])?,
                vec![Reason::SystemBinary { name: name.to_owned() }],
                "{scope:?} {name}"
            );
        }
    }
    Ok(())
}


#[test]
fn c2_finding_1_a_renamed_interpreter_is_caught_by_its_original_file_name() -> TestResult {
    let renamed = ObservedImage {
        original_file_name: Some("PowerShell.EXE".to_owned()),
        ..image("report.exe")
    };
    let by_path = ObservedImage {
        path: r"C:\Tools\python3.exe".to_owned(),
        ..image("report.exe")
    };
    for scope in WIDE_SCOPES {
        let expected = vec![Reason::SystemBinary {
            name: "report.exe".to_owned(),
        }];
        assert_eq!(hash_with(scope, vec![renamed.clone()])?, expected);
        assert_eq!(hash_with(scope, vec![by_path.clone()])?, expected);
    }
    Ok(())
}


#[test]
fn c2_finding_1_a_group_hash_of_an_interpreter_is_refused_like_the_global_one() -> TestResult {
    assert_eq!(
        hash_with(Scope::EndpointGroup, vec![image("powershell.exe")])?,
        vec![Reason::SystemBinary {
            name: "powershell.exe".to_owned()
        }]
    );
    Ok(())
}


#[test]
fn c3_finding_3_an_os_component_is_refused_at_single_endpoint_scope_too() -> TestResult {
    let expected = vec![Reason::SystemBinary {
        name: "svchost.exe".to_owned(),
    }];
    assert_eq!(hash_with(Scope::SingleEndpoint, vec![os_image("svchost.exe")])?, expected);
    Ok(())
}


#[test]
fn c2_finding_2_a_security_sensor_is_refused_at_every_scope() -> TestResult {
    for name in ["Sysmon64.exe", "SysmonDrv.sys", "MsMpEng.exe", "osqueryd", "tetragon", "agent.exe"] {
        for scope in ALL_SCOPES {
            let found = hash_with(scope, vec![sensor_image(name)])?;
            assert!(
                found.contains(&Reason::SecuritySensor { name: name.to_owned() }),
                "{scope:?} {name}: {found:?}"
            );
        }
    }
    Ok(())
}


#[test]
fn c2_finding_2_a_sensor_is_recognised_by_name_even_without_the_flag() -> TestResult {
    for name in ["Sysmon64.exe", "SysmonDrv.sys", "MsMpEng.exe", "osqueryd", "tetragon"] {
        for scope in ALL_SCOPES {
            let found = hash_with(scope, vec![image(name)])?;
            assert!(
                found.contains(&Reason::SecuritySensor { name: name.to_owned() }),
                "{scope:?} {name}: {found:?}"
            );
        }
    }
    Ok(())
}


#[test]
fn c2_finding_2_sensor_paths_are_protected_at_single_endpoint_scope() -> TestResult {
    for value in [
        r"C:\Windows\Sysmon64.exe",
        r"C:\Windows\SysmonDrv.sys",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\x.exe",
        r"C:\Program Files\Windows Defender\MsMpEng.exe",
        "/usr/bin/tetragon",
        "/usr/bin/osqueryd",
        "/etc/tetragon/x",
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert!(
            found.iter().any(|reason| matches!(reason, Reason::ProtectedPath { .. })),
            "{value}: {found:?}"
        );
    }
    Ok(())
}


#[test]
fn c2_finding_2_a_command_line_naming_a_sensor_or_a_service_tool_is_refused() -> TestResult {
    for (value, expected) in [
        ("/srv/app/bin/tool tetragon", Reason::SecuritySensor { name: "tetragon".to_owned() }),
        ("/srv/app/bin/tool Sysmon64.exe", Reason::SecuritySensor { name: "sysmon".to_owned() }),
        (
            "/usr/bin/systemctl stop tetragon",
            Reason::ServiceControlInCommandLine {
                name: "systemctl".to_owned(),
            },
        ),
        ("/usr/bin/systemctl stop tetragon", Reason::SecuritySensor { name: "tetragon".to_owned() }),
        (
            r"C:\Windows\System32\sc.exe stop Sysmon64",
            Reason::ServiceControlInCommandLine { name: "sc".to_owned() },
        ),
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, value)?;
        assert!(found.contains(&expected), "{value}: {found:?}");
    }
    Ok(())
}


#[test]
fn c2_finding_2_a_sensor_file_name_as_path_or_process_is_refused() -> TestResult {
    for kind in [SelectorKind::Path, SelectorKind::ProcessName] {
        let found = probe(Scope::SingleEndpoint, kind, "/srv/app/bin/osqueryd")?;
        assert!(found.contains(&Reason::SecuritySensor { name: "osqueryd".to_owned() }), "{found:?}");
    }
    Ok(())
}


#[test]
fn c2_finding_3_a_writable_image_is_refused_at_single_endpoint_scope() -> TestResult {
    let writable = ObservedImage {
        writable_by_non_admin: true,
        ..image("tool")
    };
    let expected = vec![Reason::WritableByNonAdmin { name: "tool".to_owned() }];
    assert_eq!(single_with(SelectorKind::Path, "/srv/app/bin/tool", vec![writable.clone()])?, expected);
    assert_eq!(hash_with(Scope::SingleEndpoint, vec![writable.clone()])?, expected);
    assert_eq!(hash_with(Scope::Global, vec![writable])?, expected);
    Ok(())
}


#[test]
fn c2_finding_3_known_writable_directories_are_refused_by_prefix() -> TestResult {
    for value in [
        r"C:\Windows\SysWOW64\Tasks\x.exe",
        r"C:\Windows\System32\spool\PRINTERS\x.exe",
        r"C:\Windows\System32\com\dmp\x.exe",
        r"C:\Windows\Registration\CRMLog\x.exe",
        r"C:\Windows\debug\WIA\x.exe",
        "/var/lib/php/sessions/x",
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert!(
            found.iter().any(|reason| matches!(reason, Reason::UserWritableDirectory { .. })),
            "{value}: {found:?}"
        );
    }
    Ok(())
}


#[test]
fn c2_finding_3_a_missing_platform_field_is_refused_at_parse_time() -> TestResult {
    let full = serde_json::to_value(crate::support::evidence())?;
    for field in ["observed_images", "signed_by_trusted"] {
        let mut partial = full.clone();
        partial.as_object_mut().map(|map| map.remove(field));
        assert!(serde_json::from_value::<Evidence>(partial).is_err(), "{field}");
    }
    let mut image_json = serde_json::to_value(image("tool"))?;
    for field in ["os_component", "security_sensor", "writable_by_non_admin", "path", "name"] {
        let mut partial = image_json.clone();
        partial.as_object_mut().map(|map| map.remove(field));
        assert!(serde_json::from_value::<ObservedImage>(partial).is_err(), "{field}");
    }
    image_json
        .as_object_mut()
        .map(|map| map.insert("extra".to_owned(), serde_json::Value::Null));
    assert!(serde_json::from_value::<ObservedImage>(image_json).is_err());
    Ok(())
}


#[test]
fn c2_finding_4_non_ascii_components_are_refused() -> TestResult {
    for value in [
        "/srv/app/bin/to\u{200b}ol",
        "/srv/app/bin/to\u{a0}ol",
        "/srv/app/bin/\u{ff5e}1",
        "/srv/app/bin/tool\u{ff1a}\u{ff1a}DATA",
        "/srv/app/\u{ff0e}\u{ff0e}/tool",
        "/srv/app/bin/\u{17f}ool",
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert_eq!(found, vec![Reason::NonCanonical { form: PathForm::NonAscii }], "{value}");
    }
    Ok(())
}


#[test]
fn c2_finding_5_detections_are_bounded_like_techniques() -> TestResult {
    let policy = loaded()?;
    let mut many = exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/app/bin/tool");
    many.impact.detections = (0..=MAX_TECHNIQUES).map(|index| (format!("T{index}"), 1)).collect();
    assert_eq!(validate(&policy, &Proposal::Exclusion(many)).reasons, vec![Reason::InputTooLarge]);
    let mut long = exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/app/bin/tool");
    long.impact.detections = [("T".repeat(MAX_TECHNIQUE_BYTES + 1), 1)].into_iter().collect();
    assert_eq!(validate(&policy, &Proposal::Exclusion(long)).reasons, vec![Reason::InputTooLarge]);
    Ok(())
}


#[test]
fn c2_finding_5_oversized_image_fields_are_refused() -> TestResult {
    let policy = loaded()?;
    let mut long_path = exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/app/bin/tool");
    long_path.evidence.observed_images = vec![ObservedImage {
        path: "a".repeat(policy_validator::rules::MAX_SELECTOR_BYTES + 1),
        ..image("tool")
    }];
    assert_eq!(validate(&policy, &Proposal::Exclusion(long_path)).reasons, vec![Reason::InputTooLarge]);
    let mut long_original = exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/app/bin/tool");
    long_original.evidence.observed_images = vec![ObservedImage {
        original_file_name: Some("a".repeat(policy_validator::rules::MAX_IMAGE_NAME_BYTES + 1)),
        ..image("tool")
    }];
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(long_original)).reasons,
        vec![Reason::InputTooLarge]
    );
    let mut long_hash = exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/app/bin/tool");
    long_hash.evidence.observed_images = vec![ObservedImage {
        sha256: "a".repeat(policy_validator::rules::MAX_IMAGE_NAME_BYTES + 1),
        ..image("tool")
    }];
    assert_eq!(validate(&policy, &Proposal::Exclusion(long_hash)).reasons, vec![Reason::InputTooLarge]);
    Ok(())
}


#[test]
fn c2_finding_6_an_os_vendor_signer_is_refused() -> TestResult {
    for signer in [
        "Microsoft Windows",
        "Microsoft Corporation",
        "Apple Inc.",
        "Canonical Ltd.",
        "Red Hat, Inc.",
        "MICROSOFT WINDOWS PUBLISHER",
    ] {
        assert_eq!(
            probe(Scope::SingleEndpoint, SelectorKind::Signer, signer)?,
            vec![Reason::OsVendorSigner],
            "{signer}"
        );
    }
    assert_eq!(probe(Scope::SingleEndpoint, SelectorKind::Signer, "Vendor Ltd")?, vec![]);
    Ok(())
}


#[test]
fn c2_finding_6_a_command_line_running_an_interpreter_is_refused() -> TestResult {
    for (value, name) in [
        (r"C:\Windows\System32\cmd.exe /c powershell -enc AAAA", "cmd"),
        (r"C:\Windows\System32\cmd.exe /c powershell -enc AAAA", "powershell"),
        ("/usr/bin/env python3", "python"),
        ("/srv/app/bin/tool /bin/sh", "sh"),
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, value)?;
        assert!(
            found.contains(&Reason::InterpreterInCommandLine { name: name.to_owned() }),
            "{value}: {found:?}"
        );
    }
    Ok(())
}


#[test]
fn c2_a_plain_command_line_is_accepted() -> TestResult {
    assert_eq!(
        probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool --verbose")?,
        vec![]
    );
    Ok(())
}
