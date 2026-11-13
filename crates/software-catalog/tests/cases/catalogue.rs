use crate::common::{apt_entry, catalogue, entry, FailingReader, TestResult, DIGEST, FINGERPRINT};
use software_catalog::catalogue::{check_entries, parse_assignment, parse_catalogue, read_text};
use software_catalog::error::CatalogueError;
use software_catalog::limits::Limits;
use software_catalog::model::{Entry, Source, Version};
use software_catalog::validate::first_problem;
use std::io::Cursor;


const SMALL_ENTRIES: usize = 2;


const SMALL_BYTES: usize = 64;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const MAX_VERSION: usize = 128;


const BOMB_DEPTH: usize = 200;


fn small() -> Limits {
    Limits {
        max_entries: SMALL_ENTRIES,
        ..Limits::default()
    }
}


fn document(body: &str) -> String {
    format!("entries:\n{body}")
}


fn problem(entry: Entry) -> Option<&'static str> {
    first_problem(&entry)
}


#[test]
fn a_full_catalogue_parses_with_every_source() -> TestResult {
    let text = document(&format!(
        "  - name: jq\n    source:\n      apt: jq\n    version:\n      pinned: 1.7.1-3build1\n    publisher: {FINGERPRINT}\n    uninstall: true\n  \
         - name: curl-rpm\n    source:\n      dnf: curl\n    version:\n      latest_approved: 7.76.1-26.el9\n    sha256: {DIGEST}\n    publisher: {FINGERPRINT}\n  \
         - name: toys\n    source:\n      winget: Microsoft.PowerToys\n    version:\n      pinned: 0.80.0\n    publisher: CN=Microsoft\n  \
         - name: tool\n    source:\n      msi: tools/tool-1.0.msi\n    version:\n      pinned: 1.0.0\n    sha256: {DIGEST}\n    publisher: CN=Vendor\n"
    ));
    let parsed = parse_catalogue(&text, &Limits::default())?;
    assert_eq!(parsed.entries.len(), SMALL_ENTRIES + SMALL_ENTRIES);
    assert_eq!(parsed.entries.first().map(|first| first.uninstall), Some(true));
    assert_eq!(
        parsed.entries.get(1).map(|second| second.version.clone()),
        Some(Version::LatestApproved("7.76.1-26.el9".to_string()))
    );
    Ok(())
}


#[test]
fn unknown_fields_and_bad_yaml_are_refused() -> TestResult {
    let unknown = document(&format!(
        "  - name: jq\n    source:\n      apt: jq\n    version:\n      pinned: 1.0\n    publisher: {FINGERPRINT}\n    extra: 1\n"
    ));
    assert!(matches!(parse_catalogue(&unknown, &Limits::default()), Err(CatalogueError::Parse(_))));
    assert!(matches!(parse_catalogue("entries: [", &Limits::default()), Err(CatalogueError::Parse(_))));
    assert!(matches!(parse_catalogue("other: 1\n", &Limits::default()), Err(CatalogueError::Parse(_))));
    Ok(())
}


#[test]
fn an_anchor_bomb_is_refused_without_expanding() -> TestResult {
    let levels: String = (0..BOMB_DEPTH)
        .map(|i| format!("l{i}: &a{i} [*a{}, *a{}]\n", i.saturating_sub(1), i.saturating_sub(1)))
        .collect();
    let bomb = format!("a0: &a0 [x]\n{levels}entries: *a{}\n", BOMB_DEPTH - 1);
    assert!(parse_catalogue(&bomb, &Limits::default()).is_err());
    Ok(())
}


#[test]
fn byte_cap_applies_at_n_and_n_plus_one() -> TestResult {
    let limits = Limits {
        max_catalogue_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    let exact = "entries: []\n".to_string() + &" ".repeat(SMALL_BYTES - "entries: []\n".len());
    assert_eq!(exact.len(), SMALL_BYTES);
    assert!(parse_catalogue(&exact, &limits)?.entries.is_empty());
    assert!(matches!(
        parse_catalogue(&format!("{exact} "), &limits),
        Err(CatalogueError::TooLarge { limit: SMALL_BYTES })
    ));
    assert!(matches!(
        parse_assignment(&format!("{exact} "), &limits),
        Err(CatalogueError::TooLarge { limit: SMALL_BYTES })
    ));
    assert!(parse_assignment("install: [a]\n", &Limits::default())?.remove.is_empty());
    assert!(matches!(
        parse_assignment("bogus: [a]\n", &Limits::default()),
        Err(CatalogueError::Parse(_))
    ));
    Ok(())
}


#[test]
fn read_text_is_bounded_and_reports_failures() -> TestResult {
    let limits = Limits {
        max_catalogue_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    assert_eq!(read_text(Cursor::new(vec![b'a'; SMALL_BYTES]), &limits)?.len(), SMALL_BYTES);
    assert!(matches!(
        read_text(Cursor::new(vec![b'a'; SMALL_BYTES + 1]), &limits),
        Err(CatalogueError::TooLarge { .. })
    ));
    assert!(matches!(
        read_text(Cursor::new(INVALID_UTF8.to_vec()), &limits),
        Err(CatalogueError::NotUtf8)
    ));
    assert!(matches!(read_text(FailingReader, &limits), Err(CatalogueError::Read(_))));
    Ok(())
}


#[test]
fn entry_count_applies_at_n_and_n_plus_one() -> TestResult {
    let names = ["a", "b", "c"];
    let make = |count: usize| catalogue(names.iter().take(count).map(|name| apt_entry(name, name, "1.0")).collect());
    assert!(check_entries(&make(SMALL_ENTRIES), &small()).is_ok());
    assert!(matches!(
        check_entries(&make(SMALL_ENTRIES + 1), &small()),
        Err(CatalogueError::TooManyEntries { limit: SMALL_ENTRIES })
    ));
    Ok(())
}


#[test]
fn duplicate_names_and_invalid_entries_are_distinct_errors() -> TestResult {
    let twice = catalogue(vec![apt_entry("jq", "jq", "1.0"), apt_entry("jq", "jq", "1.0")]);
    assert!(matches!(
        check_entries(&twice, &Limits::default()),
        Err(CatalogueError::DuplicateName { name }) if name == "jq"
    ));
    let same_package = catalogue(vec![apt_entry("jq", "jq", "1.0"), apt_entry("other", "jq", "1.0")]);
    assert!(matches!(
        check_entries(&same_package, &Limits::default()),
        Err(CatalogueError::DuplicateSource { name }) if name == "other"
    ));
    let other_manager = catalogue(vec![
        apt_entry("jq", "jq", "1.0"),
        entry("jq-rpm", Source::Dnf("jq".to_string()), "1.0-1"),
    ]);
    assert!(check_entries(&other_manager, &Limits::default()).is_ok());
    let bad = catalogue(vec![apt_entry("jq", "jq", "1.0"), apt_entry("Jq", "jq", "1.0")]);
    assert!(matches!(
        check_entries(&bad, &Limits::default()),
        Err(CatalogueError::InvalidEntry { index: 1, field: "name" })
    ));
    Ok(())
}


#[test]
fn every_field_refuses_hostile_text() -> TestResult {
    let apt = |package: &str| entry("x", Source::Apt(package.to_string()), "1.0");
    assert_eq!(problem(apt("jq")), None);
    assert_eq!(problem(apt("-oAPT::Get")), Some("source"));
    assert_eq!(problem(apt("jq\u{202e}")), Some("source"));
    assert_eq!(problem(entry("x", Source::Dnf("--exec=x".to_string()), "1.0")), Some("source"));
    assert_eq!(problem(entry("x", Source::Dnf("openssl-libs".to_string()), "1.0-1.el9")), None);
    assert_eq!(problem(entry("x", Source::Winget("a b.c".to_string()), "1.0")), Some("source"));
    assert_eq!(problem(entry("x", Source::Winget("a;b.c".to_string()), "1.0")), Some("source"));
    assert_eq!(problem(entry("x", Source::Msi("../a.msi".to_string()), "1.0")), Some("source"));
    assert_eq!(problem(entry("x", Source::Msi("/abs.msi".to_string()), "1.0")), Some("source"));
    assert_eq!(problem(entry("-x", Source::Apt("jq".to_string()), "1.0")), Some("name"));
    ["-1.0", "1.0\u{200b}", "1 0", "", "1.0\u{202e}"].iter().for_each(|version| {
        assert_eq!(
            problem(entry("x", Source::Apt("jq".to_string()), version)),
            Some("version"),
            "{version:?}"
        )
    });
    assert_eq!(problem(entry("x", Source::Dnf("curl".to_string()), "-1.0")), Some("version"));
    assert_eq!(problem(entry("x", Source::Dnf("curl".to_string()), "1.0\u{202e}")), Some("version"));
    assert_eq!(problem(entry("x", Source::Winget("a.b".to_string()), "-1")), Some("version"));
    assert_eq!(problem(entry("x", Source::Winget("a.b".to_string()), "1.0 beta")), Some("version"));
    assert_eq!(problem(entry("x", Source::Winget("a.b".to_string()), "2024-x")), None);
    Ok(())
}


#[test]
fn an_rpm_pin_is_epoch_version_release_without_extra_separators() -> TestResult {
    let dnf = |version: &str| problem(entry("x", Source::Dnf("foo".to_string()), version));
    [
        "bar-1.0-1",
        "1.0-1-1",
        "1.0",
        "1",
        ":1.0-1",
        "1:2:3-1",
        "x:1.0-1",
        "1.0-",
        "-1",
        "1.0-1.x86_64",
        "1.0-noarch",
        "1.0-1/2",
        "1/0-1",
        "1.0-1.el9.aarch64",
    ]
    .iter()
    .for_each(|version| assert_eq!(dnf(version), Some("version"), "{version}"));
    ["1:2.0-3", "1.0-1", "0:17-openjdk", "7.76.1-26.el9_8.2", "2:1.0-1.el9"]
        .iter()
        .for_each(|version| assert_eq!(dnf(version), None, "{version}"));
    Ok(())
}


#[test]
fn winget_versions_stay_option_values_and_are_bounded_text() -> TestResult {
    let winget = |version: &str| problem(entry("x", Source::Winget("a.b".to_string()), version));
    assert_eq!(winget("/quiet"), None);
    ["--exec", "-1", "a\nb", "a\u{200b}", "a\u{202e}"]
        .iter()
        .for_each(|version| assert_eq!(winget(version), Some("version"), "{version:?}"));
    assert_eq!(winget(&"1".repeat(MAX_VERSION)), None);
    assert_eq!(winget(&"1".repeat(MAX_VERSION + 1)), Some("version"));
    Ok(())
}


#[test]
fn digest_publisher_and_uninstall_rules() -> TestResult {
    let mut msi = entry("x", Source::Msi("a.msi".to_string()), "1.0");
    assert_eq!(problem(msi.clone()), Some("sha256"));
    msi.sha256 = Some(DIGEST.to_string());
    assert_eq!(problem(msi.clone()), None);
    msi.sha256 = Some(DIGEST.to_uppercase());
    assert_eq!(problem(msi.clone()), Some("sha256"));
    msi.sha256 = Some(DIGEST.to_string());
    msi.publisher = "CN=A\nB".to_string();
    assert_eq!(problem(msi.clone()), Some("publisher"));
    msi.publisher = "CN=A".to_string();
    msi.uninstall = true;
    assert_eq!(problem(msi), Some("uninstall"));
    let mut apt = apt_entry("x", "jq", "1.0");
    apt.sha256 = Some("abc".to_string());
    assert_eq!(problem(apt.clone()), Some("sha256"));
    apt.sha256 = Some(DIGEST.to_string());
    assert_eq!(problem(apt.clone()), None);
    apt.publisher = "A1B2".to_string();
    assert_eq!(problem(apt.clone()), Some("publisher"));
    apt.publisher = FINGERPRINT.to_string();
    apt.uninstall = true;
    assert_eq!(problem(apt), None);
    Ok(())
}


#[test]
fn a_debian_pin_has_upstream_and_revision_and_no_modifier_tail() -> TestResult {
    let apt = |version: &str| problem(entry("x", Source::Apt("nano".to_string()), version));
    ["7.2-", "7.2-1-", "7.2+", "7.2~", "7.2.", "-1", "1:-1", "1:"]
        .iter()
        .for_each(|version| assert_eq!(apt(version), Some("version"), "{version}"));
    ["7.2-1", "7.2", "1:7.2-1", "7.2-1~bpo1", "7.2+dfsg-1"]
        .iter()
        .for_each(|version| assert_eq!(apt(version), None, "{version}"));
    Ok(())
}


#[test]
fn the_six_extra_rpm_architectures_are_refused_in_a_release() -> TestResult {
    let dnf = |version: &str| problem(entry("x", Source::Dnf("foo".to_string()), version));
    ["i386", "i586", "armv7hl", "ppc64", "nosrc", "x86_64_v2"]
        .iter()
        .for_each(|arch| assert_eq!(dnf(&format!("1.0-1.{arch}")), Some("version"), "{arch}"));
    Ok(())
}


#[test]
fn a_dnf_entry_for_gpg_pubkey_is_refused_as_a_source() -> TestResult {
    assert_eq!(problem(entry("key", Source::Dnf("gpg-pubkey".to_string()), "1.0-1")), Some("source"));
    assert_eq!(problem(entry("key", Source::Dnf("gpg-pubkeys".to_string()), "1.0-1")), None);
    assert_eq!(problem(entry("key", Source::Dnf("bad name".to_string()), "1.0-1")), Some("source"));
    Ok(())
}
