use crate::support::{
    exclusion, hash, image, impact, loaded, probe, reasons_for, verdict_for, GOOD_PATH, GOOD_WINDOWS_PATH, HASH_PAIRS, MAX_LIFETIME, NEED_DAYS,
    NEED_VERDICTS, TECHNIQUE, YEAR,
};
use crate::types::TestResult;
use policy_validator::model::{AsrChange, AsrState, Decision, Impact, PathForm, Proposal, Reason, Scope, SelectorKind, Severity};
use policy_validator::policy::{compile, Policy, LSASS_CREDENTIAL_THEFT_RULE};
use policy_validator::rules::{
    validate, MAX_IMAGE_NAMES, MAX_IMAGE_NAME_BYTES, MAX_RULE_ID_BYTES, MAX_SELECTOR_BYTES, MAX_TECHNIQUES, MAX_TECHNIQUE_BYTES,
};
use std::collections::BTreeMap;


const LSASS_TEXT: &str = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";


const EMAIL_TEXT: &str = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";


const OFFICE_TEXT: &str = "{d4f940ab-401b-4efc-aadc-ad5f3c50688a}";


const TWO_DETECTIONS: u32 = 2;


const FIVE_REASONS: usize = 5;


const OTHER_RULE: &str = "01443614-cd74-433a-b99e-2ecdc07bfc25";


fn has(found: &[Reason], expected: &Reason) -> bool {
    found.contains(expected)
}


#[test]
fn a_narrow_signed_exclusion_is_accepted() -> TestResult {
    assert_eq!(probe(Scope::SingleEndpoint, SelectorKind::Path, GOOD_PATH)?, vec![]);
    assert_eq!(probe(Scope::SingleEndpoint, SelectorKind::Path, GOOD_WINDOWS_PATH)?, vec![]);
    assert_eq!(probe(Scope::SingleEndpoint, SelectorKind::ProcessName, GOOD_PATH)?, vec![]);
    assert_eq!(
        probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool --flag /srv/data")?,
        vec![]
    );
    assert_eq!(probe(Scope::EndpointGroup, SelectorKind::Hash, &hash())?, vec![]);
    assert_eq!(probe(Scope::Global, SelectorKind::Hash, &hash())?, vec![]);
    let accepted = verdict_for(exclusion(Scope::Global, SelectorKind::Hash, &hash()))?;
    assert_eq!(accepted.decision, Decision::Accepted);
    Ok(())
}


#[test]
fn only_a_hash_is_allowed_at_global_and_group_scope() -> TestResult {
    for scope in [Scope::Global, Scope::EndpointGroup] {
        assert_eq!(probe(scope, SelectorKind::Path, GOOD_PATH)?, vec![Reason::PathAtWideScope]);
        assert_eq!(probe(scope, SelectorKind::ProcessName, GOOD_PATH)?, vec![Reason::ProcessNameAtWideScope]);
        assert_eq!(probe(scope, SelectorKind::CommandLine, GOOD_PATH)?, vec![Reason::CommandLineAtWideScope]);
        assert_eq!(probe(scope, SelectorKind::Signer, "Vendor Inc")?, vec![Reason::SignerSelector]);
    }
    Ok(())
}


#[test]
fn a_hash_must_be_sixty_four_hexadecimal_characters() -> TestResult {
    assert_eq!(probe(Scope::EndpointGroup, SelectorKind::Hash, "abcd")?, vec![Reason::InvalidHash]);
    let not_hex = "zz".repeat(HASH_PAIRS);
    assert!(has(&probe(Scope::EndpointGroup, SelectorKind::Hash, &not_hex)?, &Reason::InvalidHash));
    let wrong_digits = hash().replacen('a', "g", 1);
    assert!(has(
        &probe(Scope::EndpointGroup, SelectorKind::Hash, &wrong_digits)?,
        &Reason::InvalidHash
    ));
    Ok(())
}


#[test]
fn a_global_hash_of_a_system_binary_or_interpreter_is_refused() -> TestResult {
    for name in [
        "powershell.exe",
        "PowerShell.EXE",
        "powershell",
        "pwsh.exe",
        "cmd.exe",
        "bash",
        "sh",
        "python3.11",
        "/usr/bin/python3.11",
        r"C:\Windows\System32\cmd.exe",
        "python311.exe",
        "bash.exe.",
        "nodejs",
        "powershell_ise.exe",
        "POWERS~1.EXE",
        "",
        "dash",
    ] {
        let mut proposal = exclusion(Scope::Global, SelectorKind::Hash, &hash());
        proposal.evidence.observed_images = vec![image("tool.exe"), image(name)];
        let found = reasons_for(proposal)?;
        assert_eq!(found, vec![Reason::SystemBinary { name: name.to_owned() }], "{name}");
    }
    Ok(())
}


#[test]
fn every_exclusion_needs_observed_images() -> TestResult {
    let mut global = exclusion(Scope::Global, SelectorKind::Hash, &hash());
    global.evidence.observed_images = Vec::new();
    assert_eq!(reasons_for(global)?, vec![Reason::NoObservedImage]);
    let mut group = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    group.evidence.observed_images = Vec::new();
    assert_eq!(reasons_for(group)?, vec![Reason::NoObservedImage]);
    Ok(())
}


#[test]
fn user_writable_directories_are_refused_in_every_spelling_that_is_canonical() -> TestResult {
    for (value, directory) in [
        ("/tmp/evil", "/tmp"),
        ("/var/tmp/evil", "/var/tmp"),
        ("/dev/shm/evil", "/dev/shm"),
        ("/home/bob/evil", "/home"),
        ("/root/evil", "/root"),
        (r"C:\Users\bob\evil.exe", r"C:\Users"),
        (r"D:\Users\bob\evil.exe", r"C:\Users"),
        (r"c:\USERS\bob\evil.exe", r"C:\Users"),
        (r"C:\Windows\Temp\x.exe", r"C:\Windows\Temp"),
        (r"C:\ProgramData\x.exe", r"C:\ProgramData"),
        ("/var/run/user/1000/evil", "/var/run/user"),
        ("/usr/tmp/evil", "/usr/tmp"),
        ("/run/lock/x", "/run/lock"),
        ("/var/lock/x", "/var/lock"),
        ("/", "/tmp"),
        (r"C:\", r"C:\Users"),
        ("/home", "/home"),
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert!(
            has(
                &found,
                &Reason::UserWritableDirectory {
                    directory: directory.to_owned()
                }
            ),
            "{value}: {found:?}"
        );
    }
    Ok(())
}


#[test]
fn a_writable_segment_anywhere_in_the_path_is_refused() -> TestResult {
    for (value, segment) in [
        ("/srv/Downloads/x", "downloads"),
        (r"C:\Vendor\AppData\x.exe", "appdata"),
        (r"C:\Program Files\X\Temp\a.exe", "temp"),
        ("/srv/tmp/x", "tmp"),
    ] {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, value)?;
        assert!(
            has(
                &found,
                &Reason::UserWritableDirectory {
                    directory: segment.to_owned()
                }
            ),
            "{value}: {found:?}"
        );
    }
    Ok(())
}


#[test]
fn the_agent_and_honeytoken_paths_are_protected() -> TestResult {
    let found = probe(Scope::SingleEndpoint, SelectorKind::Path, r"C:\Program Files\Ostyr\agent.exe")?;
    assert_eq!(
        found,
        vec![Reason::ProtectedPath {
            directory: r"C:\Program Files\Ostyr".to_owned()
        }]
    );
    assert_eq!(
        probe(Scope::SingleEndpoint, SelectorKind::Path, "/opt/ostyr")?,
        vec![
            Reason::ProtectedPath {
                directory: "/opt/ostyr".to_owned()
            },
            Reason::SecuritySensor { name: "ostyr".to_owned() },
            Reason::SecuritySensor { name: "ostyr".to_owned() }
        ]
    );
    let policy = Policy {
        honeytoken_paths: vec!["/srv/secrets/passwords.xlsx".to_owned()],
        ..Policy::default()
    };
    let custom = compile(policy, "h".to_owned())?;
    let proposal = Proposal::Exclusion(exclusion(Scope::SingleEndpoint, SelectorKind::Path, "/srv/secrets/passwords.xlsx"));
    assert_eq!(
        validate(&custom, &proposal).reasons,
        vec![Reason::ProtectedPath {
            directory: "/srv/secrets/passwords.xlsx".to_owned()
        }]
    );
    Ok(())
}


#[test]
fn a_process_name_and_a_command_line_get_the_same_path_rules() -> TestResult {
    assert_eq!(
        probe(Scope::SingleEndpoint, SelectorKind::ProcessName, "tool.exe")?,
        vec![Reason::NonCanonical { form: PathForm::NotAbsolute }]
    );
    let writable = Reason::UserWritableDirectory {
        directory: "/tmp".to_owned(),
    };
    assert!(has(&probe(Scope::SingleEndpoint, SelectorKind::ProcessName, "/tmp/evil")?, &writable));
    assert!(has(
        &probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool /tmp/evil")?,
        &writable
    ));
    assert_eq!(
        probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool -o/tmp/evil")?,
        vec![Reason::NonCanonical { form: PathForm::NotAbsolute }]
    );
    Ok(())
}


#[test]
fn a_signer_selector_is_data_not_a_pattern() -> TestResult {
    for value in ["", "*", "Ven?dor", "%SIGNER%", "Vendor\nInc"] {
        assert_eq!(
            probe(Scope::SingleEndpoint, SelectorKind::Signer, value)?,
            vec![Reason::SignerSelector],
            "{value:?}"
        );
    }
    Ok(())
}


#[test]
fn every_evidence_rule_has_its_reason() -> TestResult {
    let mut few = exclusion(Scope::SingleEndpoint, SelectorKind::Path, GOOD_PATH);
    few.evidence.benign_verdicts = 1;
    few.evidence.distinct_days = 0;
    assert_eq!(
        reasons_for(few)?,
        vec![
            Reason::TooFewVerdicts {
                have: 1,
                need: NEED_VERDICTS
            },
            Reason::TooFewDays { have: 0, need: NEED_DAYS }
        ]
    );
    let mut role = exclusion(Scope::SingleEndpoint, SelectorKind::Path, GOOD_PATH);
    role.evidence.role_match = false;
    assert_eq!(reasons_for(role)?, vec![Reason::NoRoleMatch]);
    let mut group_without_role = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    group_without_role.evidence.role_match = false;
    assert_eq!(reasons_for(group_without_role)?, vec![]);
    let mut critical = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    critical.evidence.original_severity = Severity::Critical;
    critical.evidence.honeytoken_linked = true;
    assert_eq!(reasons_for(critical)?, vec![Reason::CriticalAlert, Reason::HoneytokenLinked]);
    let mut high = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    high.evidence.original_severity = Severity::High;
    assert_eq!(reasons_for(high)?, vec![]);
    let mut long = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    long.lifetime_days = MAX_LIFETIME + 1;
    assert_eq!(
        reasons_for(long)?,
        vec![Reason::LifetimeTooLong {
            days: MAX_LIFETIME + 1,
            max: MAX_LIFETIME
        }]
    );
    Ok(())
}


#[test]
fn an_unsigned_binary_needs_a_stable_hash_and_never_a_path() -> TestResult {
    let mut path = exclusion(Scope::SingleEndpoint, SelectorKind::Path, GOOD_PATH);
    path.evidence.signed_by_trusted = false;
    assert_eq!(reasons_for(path.clone())?, vec![Reason::UnsignedWithoutHash, Reason::UnsignedPath]);
    path.evidence.known_hash = Some(hash());
    assert_eq!(reasons_for(path)?, vec![Reason::UnsignedPath, Reason::NarrowerSelector { hash: hash() }]);
    let mut unsigned_hash = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    unsigned_hash.evidence.signed_by_trusted = false;
    assert_eq!(reasons_for(unsigned_hash)?, vec![]);
    let mut unsigned_signer = exclusion(Scope::SingleEndpoint, SelectorKind::Signer, "Vendor");
    unsigned_signer.evidence.signed_by_trusted = false;
    assert_eq!(reasons_for(unsigned_signer)?, vec![Reason::SignerSelector, Reason::UnsignedWithoutHash]);
    Ok(())
}


#[test]
fn the_narrowest_selector_and_scope_win() -> TestResult {
    let mut known = exclusion(Scope::SingleEndpoint, SelectorKind::Signer, "Vendor");
    known.evidence.known_hash = Some(hash());
    assert_eq!(
        reasons_for(known)?,
        vec![Reason::SignerSelector, Reason::NarrowerSelector { hash: hash() }]
    );
    let mut same = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    same.evidence.known_hash = Some(hash());
    assert_eq!(reasons_for(same)?, vec![]);
    for seen in [0, 1] {
        let mut one = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
        one.evidence.distinct_endpoints = seen;
        assert_eq!(reasons_for(one)?, vec![Reason::NarrowerScope]);
    }
    let mut single = exclusion(Scope::SingleEndpoint, SelectorKind::Path, GOOD_PATH);
    single.evidence.distinct_endpoints = 1;
    assert_eq!(reasons_for(single)?, vec![]);
    Ok(())
}


#[test]
fn several_violations_are_all_reported() -> TestResult {
    let mut bad = exclusion(Scope::Global, SelectorKind::Path, "/tmp/evil");
    bad.evidence.benign_verdicts = 0;
    bad.evidence.signed_by_trusted = false;
    bad.evidence.distinct_endpoints = 1;
    bad.lifetime_days = YEAR;
    let found = reasons_for(bad)?;
    assert!(has(&found, &Reason::PathAtWideScope));
    assert!(has(
        &found,
        &Reason::TooFewVerdicts {
            have: 0,
            need: NEED_VERDICTS
        }
    ));
    assert!(has(&found, &Reason::UnsignedPath));
    assert!(has(&found, &Reason::NarrowerScope));
    assert!(has(
        &found,
        &Reason::LifetimeTooLong {
            days: YEAR,
            max: MAX_LIFETIME
        }
    ));
    assert!(found.len() >= FIVE_REASONS);
    Ok(())
}


#[test]
fn a_change_that_leaves_a_technique_without_detection_is_refused() -> TestResult {
    let mut last = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    last.impact.detections.insert(TECHNIQUE.to_owned(), 1);
    assert_eq!(
        reasons_for(last)?,
        vec![Reason::CoverageLoss {
            technique: TECHNIQUE.to_owned()
        }]
    );
    let mut unknown = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    unknown.impact.techniques.push("T9999".to_owned());
    assert_eq!(
        reasons_for(unknown)?,
        vec![Reason::CoverageLoss {
            technique: "T9999".to_owned()
        }]
    );
    let mut two = exclusion(Scope::EndpointGroup, SelectorKind::Hash, &hash());
    two.impact.detections.insert(TECHNIQUE.to_owned(), TWO_DETECTIONS);
    assert_eq!(reasons_for(two)?, vec![]);
    Ok(())
}


fn asr(rule_id: &str, new_state: AsrState) -> Proposal {
    Proposal::AsrChange(AsrChange {
        rule_id: rule_id.to_owned(),
        new_state,
        impact: impact(),
    })
}


#[test]
fn a_critical_asr_rule_must_stay_in_block_mode_in_any_spelling() -> TestResult {
    let policy = loaded()?;
    for text in [LSASS_TEXT, EMAIL_TEXT, OFFICE_TEXT] {
        for state in [AsrState::Disabled, AsrState::Audit, AsrState::Warn] {
            assert_eq!(validate(&policy, &asr(text, state)).reasons.len(), 1, "{text} {state:?}");
        }
        assert_eq!(validate(&policy, &asr(text, AsrState::Block)).decision, Decision::Accepted);
    }
    assert_eq!(
        validate(&policy, &asr(LSASS_TEXT, AsrState::Disabled)).reasons,
        vec![Reason::CriticalAsrRule {
            rule_id: LSASS_CREDENTIAL_THEFT_RULE
        }]
    );
    assert_eq!(validate(&policy, &asr(OTHER_RULE, AsrState::Disabled)).decision, Decision::Accepted);
    assert_eq!(
        validate(&policy, &asr("not-a-guid", AsrState::Block)).reasons,
        vec![Reason::InvalidAsrRuleId]
    );
    Ok(())
}


#[test]
fn an_asr_change_is_subject_to_the_coverage_rule() -> TestResult {
    let policy = loaded()?;
    let proposal = Proposal::AsrChange(AsrChange {
        rule_id: OTHER_RULE.to_owned(),
        new_state: AsrState::Disabled,
        impact: Impact {
            techniques: vec![TECHNIQUE.to_owned()],
            detections: BTreeMap::new(),
        },
    });
    assert_eq!(
        validate(&policy, &proposal).reasons,
        vec![Reason::CoverageLoss {
            technique: TECHNIQUE.to_owned()
        }]
    );
    Ok(())
}


#[test]
fn an_oversized_field_is_refused_before_anything_is_read() -> TestResult {
    let policy = loaded()?;
    let big = "a".repeat(MAX_SELECTOR_BYTES + 1);
    let mut selector = exclusion(Scope::SingleEndpoint, SelectorKind::CommandLine, &big);
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(selector.clone())).reasons,
        vec![Reason::InputTooLarge]
    );
    selector.selector.value = "/srv/x".to_owned();
    selector.evidence.known_hash = Some(big.clone());
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(selector.clone())).reasons,
        vec![Reason::InputTooLarge]
    );
    selector.evidence.known_hash = None;
    selector.evidence.observed_images = vec![image("a"); MAX_IMAGE_NAMES + 1];
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(selector.clone())).reasons,
        vec![Reason::InputTooLarge]
    );
    selector.evidence.observed_images = vec![image(&"a".repeat(MAX_IMAGE_NAME_BYTES + 1))];
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(selector.clone())).reasons,
        vec![Reason::InputTooLarge]
    );
    selector.evidence.observed_images = vec![image("a")];
    selector.impact.techniques = vec!["T".to_owned(); MAX_TECHNIQUES + 1];
    assert_eq!(
        validate(&policy, &Proposal::Exclusion(selector.clone())).reasons,
        vec![Reason::InputTooLarge]
    );
    selector.impact.techniques = vec!["T".repeat(MAX_TECHNIQUE_BYTES + 1)];
    assert_eq!(validate(&policy, &Proposal::Exclusion(selector)).reasons, vec![Reason::InputTooLarge]);
    assert_eq!(validate(&policy, &asr(&big, AsrState::Block)).reasons, vec![Reason::InputTooLarge]);
    let long_id = "a".repeat(MAX_RULE_ID_BYTES + 1);
    assert_eq!(validate(&policy, &asr(&long_id, AsrState::Block)).reasons, vec![Reason::InputTooLarge]);
    let mut crowded = impact();
    crowded.techniques = vec!["T".to_owned(); MAX_TECHNIQUES + 1];
    let proposal = Proposal::AsrChange(AsrChange {
        rule_id: OTHER_RULE.to_owned(),
        new_state: AsrState::Block,
        impact: crowded,
    });
    assert_eq!(validate(&policy, &proposal).reasons, vec![Reason::InputTooLarge]);
    Ok(())
}


#[test]
fn the_verdict_carries_the_version_and_every_reason_has_a_message() -> TestResult {
    let accepted = verdict_for(exclusion(Scope::Global, SelectorKind::Hash, &hash()))?;
    assert_eq!(accepted.version, format!("{}+test-hash", env!("CARGO_PKG_VERSION")));
    let refused = verdict_for(exclusion(Scope::Global, SelectorKind::Path, GOOD_PATH))?;
    assert_eq!(refused.decision, Decision::Refused);
    assert!(refused.reasons.iter().all(|reason| reason.to_string().contains(": ")));
    let text = serde_json::to_string(&refused)?;
    assert!(text.contains("\"reason\":\"path_at_wide_scope\""));
    Ok(())
}


#[test]
fn an_unknown_field_in_a_proposal_is_refused_by_the_parser() -> TestResult {
    let good = serde_json::to_value(Proposal::Exclusion(exclusion(Scope::Global, SelectorKind::Hash, &hash())))?;
    assert!(serde_json::from_value::<Proposal>(good.clone()).is_ok());
    let mut extra = good.clone();
    if let Some(object) = extra.as_object_mut() {
        object.insert("surprise".to_owned(), serde_json::json!(true));
    }
    assert!(serde_json::from_value::<Proposal>(extra).is_err());
    let mut nested = good;
    if let Some(object) = nested.get_mut("selector").and_then(serde_json::Value::as_object_mut) {
        object.insert("surprise".to_owned(), serde_json::json!(true));
    }
    assert!(serde_json::from_value::<Proposal>(nested).is_err());
    Ok(())
}
