use crate::common::{apt_entry, entry, TestResult, DIGEST};
use software_catalog::args::{arguments, FIXED_FLAGS};
use software_catalog::model::{ActionKind, Entry, Source};


fn vector(kind: ActionKind, entry: &Entry) -> Vec<String> {
    arguments(kind, entry)
}


#[test]
fn each_source_builds_its_exact_vector() -> TestResult {
    let apt = apt_entry("jq", "jq", "1.7.1-3");
    let dnf = entry("curl", Source::Dnf("curl".to_string()), "7.76.1-26.el9");
    let dnf_epoch = entry("curl", Source::Dnf("curl".to_string()), "2:7.76.1-26.el9");
    let winget = entry("toys", Source::Winget("Microsoft.PowerToys".to_string()), "0.80.0");
    let mut msi = entry("tool", Source::Msi("tools/tool.msi".to_string()), "1.0.0");
    msi.sha256 = Some(DIGEST.to_string());
    assert_eq!(
        vector(ActionKind::Install, &apt),
        ["apt-get", "install", "-y", "--no-remove", "jq=1.7.1-3"]
    );
    assert_eq!(
        vector(ActionKind::Update, &apt),
        ["apt-get", "install", "-y", "--no-remove", "jq=1.7.1-3"]
    );
    assert_eq!(vector(ActionKind::Uninstall, &apt), ["dpkg", "--remove", "jq"]);
    assert_eq!(
        vector(ActionKind::Install, &dnf),
        ["dnf", "install", "-y", "--setopt=obsoletes=False", "curl-0:7.76.1-26.el9"]
    );
    assert_eq!(
        vector(ActionKind::Update, &dnf_epoch),
        ["dnf", "install", "-y", "--setopt=obsoletes=False", "curl-2:7.76.1-26.el9"]
    );
    assert_eq!(vector(ActionKind::Uninstall, &dnf), ["rpm", "--erase", "curl"]);
    assert_eq!(
        vector(ActionKind::Install, &winget),
        ["winget", "install", "--id", "Microsoft.PowerToys", "--version", "0.80.0", "--exact"]
    );
    assert_eq!(
        vector(ActionKind::Update, &winget),
        ["winget", "upgrade", "--id", "Microsoft.PowerToys", "--version", "0.80.0", "--exact"]
    );
    assert_eq!(
        vector(ActionKind::Uninstall, &winget),
        ["winget", "uninstall", "--id", "Microsoft.PowerToys", "--exact"]
    );
    assert_eq!(vector(ActionKind::Install, &msi), ["msiexec", "/i", "tools/tool.msi", "/qn"]);
    assert_eq!(vector(ActionKind::Update, &msi), ["msiexec", "/i", "tools/tool.msi", "/qn"]);
    assert!(vector(ActionKind::Uninstall, &msi).is_empty());
    [
        ActionKind::NewerThanCatalogue,
        ActionKind::Unknown,
        ActionKind::NotInCatalogue,
        ActionKind::Unavailable,
        ActionKind::Held,
    ]
    .iter()
    .for_each(|kind| assert!(vector(*kind, &apt).is_empty()));
    Ok(())
}


#[test]
fn no_argument_starts_with_a_dash_except_the_fixed_flags() -> TestResult {
    let entries = [
        apt_entry("jq", "jq", "1.7.1-3"),
        entry("curl", Source::Dnf("curl".to_string()), "7.76.1-26.el9"),
        entry("toys", Source::Winget("Microsoft.PowerToys".to_string()), "0.80.0"),
        entry("tool", Source::Msi("tools/tool.msi".to_string()), "1.0.0"),
    ];
    let kinds = [ActionKind::Install, ActionKind::Update, ActionKind::Uninstall];
    entries.iter().for_each(|item| {
        kinds.iter().for_each(|kind| {
            arguments(*kind, item)
                .iter()
                .filter(|argument| argument.starts_with('-'))
                .for_each(|argument| assert!(FIXED_FLAGS.contains(&argument.as_str()), "{argument}"));
        });
    });
    Ok(())
}
