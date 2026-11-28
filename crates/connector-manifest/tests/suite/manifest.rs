use crate::common::types::TestResult;
use crate::common::{manifest_with, VALID_MANIFEST};
use connector_manifest::bounded::TOO_MANY_ELEMENTS;
use connector_manifest::error::ConnectorError;
use connector_manifest::manifest::{in_grammar, parse_manifest, valid_file_name, valid_name, valid_scope};
use connector_manifest::model::{
    Access, Approval, ConfigKind, Runtime, MAX_ACTIONS, MAX_ALIASES, MAX_CONFIG_FIELDS, MAX_DEFAULT_BYTES, MAX_FILE_NAME_BYTES, MAX_MANIFEST_BYTES,
    MAX_NAME_BYTES, MAX_RIGHTS, MAX_SCOPE_BYTES, MAX_TARGETS, MAX_VERSION_BYTES,
};


const HUGE_MANIFEST_BYTES: usize = 1_048_576;


const HUGE_ACTION_COUNT: usize = 100_000;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const ALIAS_LEVELS: usize = 12;


const ALIAS_FANOUT: usize = 9;


fn refused(text: &str) -> Result<ConnectorError, Box<dyn std::error::Error>> {
    match parse_manifest(text.as_bytes()) {
        Ok(_) => Err("manifest accepted".into()),
        Err(error) => Ok(error),
    }
}


fn invalid_field(text: &str) -> Result<&'static str, Box<dyn std::error::Error>> {
    match refused(text)? {
        ConnectorError::Invalid { field } => Ok(field),
        other => Err(format!("unexpected error: {other}").into()),
    }
}


fn rights_manifest(count: usize) -> String {
    let entries = "  - scope: a\n    access: read\n".repeat(count);
    manifest_with(
        "rights:\n  - scope: devices:inventory\n    access: read\n",
        &format!("rights:\n{entries}"),
    )
}


fn actions_manifest(count: usize) -> String {
    let entries: String = (0..count)
        .map(|i| format!("  - name: a{i}\n    targets: []\n    default_approval: human\n"))
        .collect();
    manifest_with(
        "actions:\n  - name: restart-service\n    targets: [devices:inventory]\n    default_approval: human\n",
        &format!("actions:\n{entries}"),
    )
}


#[test]
fn a_valid_manifest_parses_with_every_field() -> TestResult {
    let manifest = parse_manifest(VALID_MANIFEST.as_bytes())?;
    assert_eq!(manifest.name, "example-sync");
    assert_eq!(manifest.version.to_string(), "1.2.3");
    assert_eq!(manifest.publisher, "acme");
    assert_eq!(manifest.rights.first().map(|right| right.access), Some(Access::Read));
    assert_eq!(manifest.actions.first().map(|action| action.default_approval), Some(Approval::Human));
    assert_eq!(manifest.config.get(1).map(|field| field.kind), Some(ConfigKind::SecretFile));
    Ok(())
}


#[test]
fn a_manifest_at_each_count_limit_is_accepted() -> TestResult {
    parse_manifest(rights_manifest(MAX_RIGHTS).as_bytes())?;
    parse_manifest(actions_manifest(MAX_ACTIONS).as_bytes())?;
    Ok(())
}


#[test]
fn one_element_over_each_count_is_refused() -> TestResult {
    let config_entries = "  - name: a\n    kind: string\n    required: false\n".repeat(MAX_CONFIG_FIELDS + 1);
    let config = manifest_with(
        "config:\n  - name: base-url\n    kind: string\n    required: true\n  - name: token-file\n    kind: secret_file\n    required: true\n",
        &format!("config:\n{config_entries}"),
    );
    let targets = (0..=MAX_TARGETS).map(|i| format!("t{i}")).collect::<Vec<_>>().join(", ");
    let target_manifest = manifest_with("[devices:inventory]", &format!("[{targets}]"));
    [
        rights_manifest(MAX_RIGHTS + 1),
        actions_manifest(MAX_ACTIONS + 1),
        config,
        target_manifest,
    ]
    .iter()
    .try_for_each(|text| {
        let message = refused(text)?.to_string();
        assert!(message.contains(TOO_MANY_ELEMENTS), "{message}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_element_after_the_cap_is_never_built() -> TestResult {
    let entries = "  - name: a\n    targets: []\n    default_approval: human\n".repeat(MAX_ACTIONS);
    let text = manifest_with(
        "actions:\n  - name: restart-service\n    targets: [devices:inventory]\n    default_approval: human\n",
        &format!("actions:\n{entries}  - name: a\n    targets: []\n    default_approval: human\n  - bogus: 1\n"),
    );
    let message = refused(&text)?.to_string();
    assert!(message.contains(TOO_MANY_ELEMENTS), "{message}");
    Ok(())
}


#[test]
fn a_megabyte_manifest_of_actions_is_refused_by_size_before_any_parse() -> TestResult {
    let entries = "  - name: a\n    targets: []\n    default_approval: human\n".repeat(HUGE_ACTION_COUNT);
    let text = format!("actions:\n{entries}");
    assert!(text.len() > HUGE_MANIFEST_BYTES);
    assert!(matches!(refused(&text)?, ConnectorError::ManifestTooLarge { max } if max == MAX_MANIFEST_BYTES));
    Ok(())
}


#[test]
fn a_manifest_at_the_size_cap_is_read_and_one_byte_more_is_refused() -> TestResult {
    let padding = " ".repeat(MAX_MANIFEST_BYTES - VALID_MANIFEST.len());
    parse_manifest(format!("{VALID_MANIFEST}{padding}").as_bytes())?;
    let over = format!("{VALID_MANIFEST}{padding} ");
    assert!(matches!(refused(&over)?, ConnectorError::ManifestTooLarge { .. }));
    Ok(())
}


#[test]
fn an_unknown_key_at_any_level_is_refused() -> TestResult {
    [
        format!("{VALID_MANIFEST}extra: 1\n"),
        manifest_with("access: read", "access: read\n    extra: 1"),
        manifest_with("required: true", "required: true\n    extra: 1"),
    ]
    .iter()
    .try_for_each(|text| {
        assert!(matches!(refused(text)?, ConnectorError::Document { .. }));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


fn alias_manifest(count: usize) -> String {
    let first = "  - name: a0\n    kind: string\n    required: true\n    default: &d x\n";
    let rest: String = (1..count)
        .map(|i| format!("  - name: a{i}\n    kind: string\n    required: true\n    default: *d\n"))
        .collect();
    manifest_with(
        "config:\n  - name: base-url\n    kind: string\n    required: true\n  - name: token-file\n    kind: secret_file\n    required: true\n",
        &format!("config:\n{first}{rest}"),
    )
}


#[test]
fn aliases_up_to_the_fixed_count_are_accepted_and_beyond_it_refused() -> TestResult {
    let fine = parse_manifest(alias_manifest(MAX_ALIASES).as_bytes())?;
    assert_eq!(fine.config.last().and_then(|field| field.default.as_deref()), Some("x"));
    assert!(matches!(refused(&alias_manifest(MAX_ALIASES + 1 + 1))?, ConnectorError::Document { .. }));
    Ok(())
}


#[test]
fn a_nested_alias_bomb_in_an_unknown_key_is_refused() -> TestResult {
    let mut lines = vec!["l0: &l0 [x, x, x, x, x, x, x, x, x]".to_owned()];
    lines.extend((1..ALIAS_LEVELS).map(|level| {
        let previous = format!("*l{}", level - 1);
        format!("l{level}: &l{level} [{}]", vec![previous; ALIAS_FANOUT].join(", "))
    }));
    let text = format!("{VALID_MANIFEST}{}\n", lines.join("\n"));
    assert!(matches!(refused(&text)?, ConnectorError::Document { .. }));
    Ok(())
}


#[test]
fn a_manifest_that_is_not_text_or_not_a_version_is_refused() -> TestResult {
    assert_eq!(
        match parse_manifest(&INVALID_UTF8) {
            Err(ConnectorError::Invalid { field }) => field,
            _ => "other",
        },
        "encoding"
    );
    assert!(matches!(refused(&manifest_with("1.2.3", "one"))?, ConnectorError::Document { .. }));
    Ok(())
}


#[test]
fn names_are_an_ascii_allowlist_that_never_starts_with_a_dash() -> TestResult {
    assert_eq!(invalid_field(&manifest_with("name: example-sync", "name: -example"))?, "name");
    assert_eq!(invalid_field(&manifest_with("name: example-sync", "name: Example"))?, "name");
    assert_eq!(invalid_field(&manifest_with("name: example-sync", "name: \"\""))?, "name");
    assert_eq!(invalid_field(&manifest_with("name: example-sync", "name: caf\u{e9}"))?, "name");
    assert_eq!(invalid_field(&manifest_with("publisher: acme", "publisher: \"-acme\""))?, "publisher");
    assert_eq!(
        invalid_field(&manifest_with("scope: devices:inventory", "scope: \"-x\""))?,
        "rights.scope"
    );
    assert_eq!(invalid_field(&manifest_with("name: restart-service", "name: \"-r\""))?, "actions.name");
    assert_eq!(
        invalid_field(&manifest_with("targets: [devices:inventory]", "targets: [\"-t\"]"))?,
        "actions.targets"
    );
    assert_eq!(invalid_field(&manifest_with("name: base-url", "name: \"-b\""))?, "config.name");
    let long = "a".repeat(MAX_NAME_BYTES + 1);
    assert_eq!(invalid_field(&manifest_with("name: example-sync", &format!("name: {long}")))?, "name");
    Ok(())
}


#[test]
fn duplicate_action_or_field_names_are_refused() -> TestResult {
    let action = "  - name: restart-service\n    targets: []\n    default_approval: human\n";
    let field = "  - name: base-url\n    kind: string\n    required: true\n";
    assert_eq!(
        invalid_field(&VALID_MANIFEST.replacen("config:", &format!("{action}config:"), 1))?,
        "actions.name"
    );
    assert_eq!(invalid_field(&format!("{VALID_MANIFEST}{field}"))?, "config.name");
    Ok(())
}


#[test]
fn a_secret_file_never_carries_a_default_and_other_defaults_are_bounded() -> TestResult {
    assert_eq!(
        invalid_field(&manifest_with(
            "kind: secret_file\n    required: true",
            "kind: secret_file\n    required: true\n    default: /etc/key"
        ))?,
        "config.default"
    );
    let long = "a".repeat(MAX_DEFAULT_BYTES + 1);
    assert_eq!(
        invalid_field(&manifest_with(
            "kind: string\n    required: true",
            &format!("kind: string\n    required: true\n    default: {long}")
        ))?,
        "config.default"
    );
    let fine = manifest_with(
        "kind: string\n    required: true",
        "kind: string\n    required: true\n    default: http://localhost",
    );
    assert_eq!(
        parse_manifest(fine.as_bytes())?
            .config
            .first()
            .and_then(|field| field.default.clone())
            .as_deref(),
        Some("http://localhost")
    );
    Ok(())
}


#[test]
fn the_grammar_functions_apply_their_length_and_character_rules() -> TestResult {
    assert!(valid_name("a.b_c-d9"));
    assert!(!valid_name("a b"));
    assert!(valid_scope("devices:read"));
    assert!(!valid_scope("a".repeat(MAX_SCOPE_BYTES + 1).as_str()));
    assert!(valid_file_name("Main.py"));
    assert!(!valid_file_name(".hidden"));
    assert!(!valid_file_name("a".repeat(MAX_FILE_NAME_BYTES + 1).as_str()));
    assert!(!in_grammar("", MAX_NAME_BYTES, char::is_alphanumeric, char::is_alphanumeric));
    Ok(())
}


const VERSION_PREFIX: &str = "1.0.0-";


#[test]
fn a_version_over_the_cap_is_refused_before_parsing_and_one_at_the_cap_is_read() -> TestResult {
    let long = format!("{VERSION_PREFIX}{}", "a".repeat(MAX_VERSION_BYTES + 1 - VERSION_PREFIX.len()));
    assert_eq!(long.len(), MAX_VERSION_BYTES + 1);
    assert!(matches!(
        refused(&manifest_with("1.2.3", &long))?,
        ConnectorError::Document { message, .. } if message.contains("`version`")
    ));
    let exact = format!("{VERSION_PREFIX}{}", "a".repeat(MAX_VERSION_BYTES - VERSION_PREFIX.len()));
    assert_eq!(parse_manifest(manifest_with("1.2.3", &exact).as_bytes())?.version.to_string(), exact);
    Ok(())
}


#[test]
fn the_entry_and_the_runtime_are_required_and_the_entry_is_a_package_file_name() -> TestResult {
    let manifest = parse_manifest(VALID_MANIFEST.as_bytes())?;
    assert_eq!(manifest.entry, "main.py");
    assert_eq!(manifest.runtime, Runtime::Python3);
    assert_eq!(
        parse_manifest(manifest_with("runtime: python3", "runtime: native").as_bytes())?.runtime,
        Runtime::Native
    );
    assert!(matches!(
        refused(&VALID_MANIFEST.replacen("entry: main.py\n", "", 1))?,
        ConnectorError::Document { .. }
    ));
    assert!(matches!(
        refused(&VALID_MANIFEST.replacen("runtime: python3\n", "", 1))?,
        ConnectorError::Document { .. }
    ));
    assert!(matches!(
        refused(&manifest_with("runtime: python3", "runtime: perl"))?,
        ConnectorError::Document { .. }
    ));
    assert!(matches!(
        refused(&manifest_with("runtime: python3", "runtime: python3\nruntime: native"))?,
        ConnectorError::Document { .. }
    ));
    Ok(())
}


#[test]
fn an_entry_outside_the_file_name_grammar_or_naming_the_manifest_or_the_signature_is_refused() -> TestResult {
    let bad = [
        "-main.py",
        "../main.py",
        "a/b",
        ".hidden",
        "connector.yaml",
        "connector.sig",
        "\"\"",
        "caf\u{e9}",
    ];
    bad.iter().try_for_each(
        |entry| match invalid_field(&manifest_with("entry: main.py", &format!("entry: {entry}"))) {
            Ok("entry") => Ok(()),
            other => Err(format!("{entry}: {other:?}")),
        },
    )?;
    assert_eq!(
        parse_manifest(manifest_with("entry: main.py", "entry: run-2.sh").as_bytes())?.entry,
        "run-2.sh"
    );
    Ok(())
}
