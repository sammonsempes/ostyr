use device_control::error::{PolicyError, RenderError, ValidationError};
use device_control::extension_grammar::{is_chromium_id, is_firefox_id, is_update_url};
use device_control::extensions::{parse_extension_policy, Browser, ExtensionAction, ExtensionPolicy};
use device_control::limits::{MAX_EXTENSIONS, MAX_POLICY_BYTES, MAX_UPDATE_URL_BYTES};
use device_control::model::{Action, Mode};
use device_control::render_extensions::{render_chromium, render_firefox};
use std::error::Error;


const FIXTURE: &str = include_str!("fixtures/extensions.yaml");


const GOLDEN_CHROMIUM: &str = include_str!("fixtures/extensions.chromium.json");


const GOLDEN_FIREFOX: &str = include_str!("fixtures/extensions.firefox.json");


const CHROMIUM_ID: &str = "cjpalhdlnbpafiamejdnhcphjbkeiagm";


const FIXTURE_EXTENSIONS: usize = 5;


const BAD_INDEX: usize = 1;


const FORCED_COUNT: usize = 2;


const LONG_LOCAL: usize = 65;


const LONG_DOMAIN: usize = 191;


fn parse(text: &str) -> Result<ExtensionPolicy, PolicyError> {
    parse_extension_policy(&mut text.as_bytes(), "extensions.yaml")
}


fn entry(browser: &str, id: &str, action: &str, rest: &str) -> String {
    format!("mode: enforce\ndefault: allow\nextensions:\n  - {{browser: {browser}, id: \"{id}\", action: {action}, owner: bob, reason: ok{rest}}}\n")
}


fn fixture() -> Result<ExtensionPolicy, Box<dyn Error>> {
    Ok(parse(FIXTURE)?)
}


#[test]
fn fixture_parses() -> Result<(), Box<dyn Error>> {
    let policy = fixture()?;
    assert_eq!(policy.extensions.len(), FIXTURE_EXTENSIONS);
    assert_eq!(policy.mode, Mode::Enforce);
    assert_eq!(policy.default, Action::Block);
    assert_eq!(
        policy
            .extensions
            .iter()
            .filter(|extension| extension.action == ExtensionAction::Force)
            .count(),
        FORCED_COUNT
    );
    assert!(policy.extensions.iter().any(|extension| extension.browser == Browser::Firefox));
    Ok(())
}


#[test]
fn mode_defaults_to_audit() -> Result<(), Box<dyn Error>> {
    let policy = parse("default: allow\n")?;
    assert_eq!(policy.mode, Mode::Audit);
    assert!(policy.extensions.is_empty());
    Ok(())
}


#[test]
fn golden_bytes() -> Result<(), Box<dyn Error>> {
    let policy = fixture()?;
    assert_eq!(render_chromium(&policy)?, GOLDEN_CHROMIUM);
    assert_eq!(render_firefox(&policy)?, GOLDEN_FIREFOX);
    Ok(())
}


#[test]
fn render_is_deterministic() -> Result<(), Box<dyn Error>> {
    let policy = fixture()?;
    assert_eq!(render_chromium(&policy)?, render_chromium(&policy)?);
    assert_eq!(render_firefox(&policy)?, render_firefox(&policy)?);
    Ok(())
}


#[test]
fn default_allow_renders_allowed_wildcard() -> Result<(), Box<dyn Error>> {
    let policy = parse("mode: enforce\ndefault: allow\n")?;
    assert!(render_chromium(&policy)?.contains("\"installation_mode\": \"allowed\""));
    assert!(render_firefox(&policy)?.contains("\"policies\""));
    Ok(())
}


#[test]
fn default_block_without_entry_blocks_all() -> Result<(), Box<dyn Error>> {
    let policy = parse("mode: enforce\ndefault: block\n")?;
    assert_eq!(
        render_chromium(&policy)?,
        "{\n  \"ExtensionSettings\": {\n    \"*\": {\n      \"installation_mode\": \"blocked\"\n    }\n  }\n}\n"
    );
    Ok(())
}


#[test]
fn audit_is_refused_by_both_renderers() -> Result<(), Box<dyn Error>> {
    let policy = parse(&FIXTURE.replace("mode: enforce", "mode: audit"))?;
    assert!(matches!(render_chromium(&policy), Err(RenderError::AuditMode)));
    assert!(matches!(render_firefox(&policy), Err(RenderError::AuditMode)));
    Ok(())
}


#[test]
fn chromium_id_grammar() -> Result<(), Box<dyn Error>> {
    assert!(is_chromium_id(CHROMIUM_ID));
    assert!(!is_chromium_id(&CHROMIUM_ID.chars().take(CHROMIUM_ID.len() - 1).collect::<String>()));
    assert!(!is_chromium_id(&format!("{CHROMIUM_ID}a")));
    assert!(!is_chromium_id(&CHROMIUM_ID.replace('c', "q")));
    assert!(!is_chromium_id(&CHROMIUM_ID.to_uppercase()));
    assert!(!is_chromium_id(&CHROMIUM_ID.replace('c', "\u{3164}")));
    Ok(())
}


#[test]
fn firefox_id_grammar() -> Result<(), Box<dyn Error>> {
    assert!(is_firefox_id("{446900e4-71c2-419f-a6a7-df9c091e268b}"));
    assert!(is_firefox_id("{446900E4-71C2-419F-A6A7-DF9C091E268B}"));
    assert!(is_firefox_id("uBlock0@raymondhill.net"));
    assert!(!is_firefox_id("{446900e4-71c2-419f-a6a7-df9c091e268}"));
    assert!(!is_firefox_id("{446900e4-71c2-419f-a6a7-df9c091e268g}"));
    assert!(!is_firefox_id("[446900e4-71c2-419f-a6a7-df9c091e268b]"));
    assert!(!is_firefox_id("-x@example.org"));
    assert!(!is_firefox_id(".x@example.org"));
    assert!(!is_firefox_id(""));
    assert!(!is_firefox_id("noat"));
    assert!(!is_firefox_id("@example.org"));
    assert!(!is_firefox_id("x@"));
    assert!(!is_firefox_id("x@example.org\u{202e}"));
    assert!(!is_firefox_id("x\u{3164}@example.org"));
    assert!(!is_firefox_id("x@exa mple.org"));
    assert!(!is_firefox_id("x\"@example.org"));
    assert!(is_firefox_id(&format!("{}@e.org", "a".repeat(LONG_LOCAL - 1))));
    assert!(!is_firefox_id(&format!("{}@e.org", "a".repeat(LONG_LOCAL))));
    assert!(is_firefox_id(&format!("x@{}", "a".repeat(LONG_DOMAIN - 1))));
    assert!(!is_firefox_id(&format!("x@{}", "a".repeat(LONG_DOMAIN))));
    Ok(())
}


#[test]
fn update_url_grammar() -> Result<(), Box<dyn Error>> {
    assert!(is_update_url("https://example.org/a/b.xpi?x=1&y=2"));
    assert!(is_update_url("https://example.org:8443/a"));
    assert!(!is_update_url("http://example.org/a"));
    assert!(!is_update_url("https://user@example.org/a"));
    assert!(!is_update_url("https://example.org/%2e%2e"));
    assert!(!is_update_url("https://example.org/a\"b"));
    assert!(!is_update_url("https://example.org/a\\b"));
    assert!(!is_update_url("https://example.org/a b"));
    assert!(!is_update_url("https://example.org/a\nb"));
    assert!(!is_update_url("https://example.org/\u{3164}"));
    assert!(!is_update_url("https://example.org/\u{202e}"));
    assert!(!is_update_url("https://"));
    assert!(!is_update_url("https:///path"));
    assert!(!is_update_url("https://?x"));
    assert!(!is_update_url("https://-host/a"));
    assert!(!is_update_url("https://exa mple.org/a"));
    assert!(!is_update_url("example.org"));
    assert!(is_update_url(&format!(
        "https://e.org/{}",
        "a".repeat(MAX_UPDATE_URL_BYTES - "https://e.org/".len())
    )));
    assert!(!is_update_url(&format!("https://e.org/{}", "a".repeat(MAX_UPDATE_URL_BYTES))));
    Ok(())
}


#[test]
fn bad_ids_are_refused_while_parsing() -> Result<(), Box<dyn Error>> {
    assert!(parse(&entry("chromium", &CHROMIUM_ID.replace('c', "q"), "allow", "")).is_err());
    assert!(parse(&entry("chromium", "x@example.org", "allow", "")).is_err());
    assert!(parse(&entry("firefox", CHROMIUM_ID, "allow", "")).is_err());
    assert!(parse(&entry("firefox", "-x@example.org", "allow", "")).is_err());
    Ok(())
}


#[test]
fn injection_attempts_never_reach_a_render() -> Result<(), Box<dyn Error>> {
    ["a\\\"}, \\\"b\\\": {", "x@e.org\\n}", "x@e.org\\\"", "x@e.org}"]
        .iter()
        .for_each(|id| assert!(parse(&entry("firefox", id, "allow", "")).is_err()));
    let url = ", update_url: \"https://e.org/\\\", \\\"x\\\": {\"";
    assert!(parse(&entry("chromium", CHROMIUM_ID, "force", url)).is_err());
    Ok(())
}


#[test]
fn error_kinds_name_the_index_not_the_value() -> Result<(), Box<dyn Error>> {
    let duplicate = format!(
        "default: allow\nextensions:\n  - {{browser: chromium, id: {CHROMIUM_ID}, action: allow, owner: bob, reason: ok}}\n  - {{browser: chromium, id: {CHROMIUM_ID}, action: block, owner: bob, reason: ok}}\n"
    );
    let error = parse(&duplicate).err().ok_or("duplicate accepted")?;
    assert!(matches!(
        error,
        PolicyError::Extension {
            index: BAD_INDEX,
            source: ValidationError::DuplicateExtension,
            ..
        }
    ));
    assert!(!error.to_string().contains(CHROMIUM_ID));
    Ok(())
}


#[test]
fn duplicate_firefox_id_in_another_case_is_refused() -> Result<(), Box<dyn Error>> {
    let text = "default: allow\nextensions:\n  - {browser: firefox, id: A@e.org, action: block, owner: bob, reason: ok}\n  - {browser: firefox, id: a@E.ORG, action: force, update_url: \"https://e.org/x.xpi\", owner: bob, reason: ok}\n";
    assert!(matches!(
        parse(text),
        Err(PolicyError::Extension {
            index: BAD_INDEX,
            source: ValidationError::DuplicateExtension,
            ..
        })
    ));
    Ok(())
}


#[test]
fn same_id_for_two_browsers_is_allowed() -> Result<(), Box<dyn Error>> {
    let text = "default: allow\nextensions:\n  - {browser: firefox, id: a@e.org, action: block, owner: bob, reason: ok}\n  - {browser: chromium, id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, action: block, owner: bob, reason: ok}\n";
    assert!(parse(text).is_ok());
    Ok(())
}


#[test]
fn force_needs_a_url_and_others_refuse_one() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        parse(&entry("chromium", CHROMIUM_ID, "force", "")),
        Err(PolicyError::Extension {
            source: ValidationError::UpdateUrlRequired,
            ..
        })
    ));
    assert!(matches!(
        parse(&entry("chromium", CHROMIUM_ID, "block", ", update_url: \"https://e.org/x\"")),
        Err(PolicyError::Extension {
            source: ValidationError::UpdateUrlForbidden,
            ..
        })
    ));
    assert!(matches!(
        parse(&entry("chromium", CHROMIUM_ID, "allow", ", update_url: \"https://e.org/x\"")),
        Err(PolicyError::Extension {
            source: ValidationError::UpdateUrlForbidden,
            ..
        })
    ));
    assert!(parse(&entry("chromium", CHROMIUM_ID, "force", ", update_url: \"http://e.org/x\"")).is_err());
    assert!(parse(&entry("chromium", CHROMIUM_ID, "force", ", update_url: \"https://e.org/x\"")).is_ok());
    Ok(())
}


#[test]
fn hidden_text_in_owner_and_reason_is_refused() -> Result<(), Box<dyn Error>> {
    let owner = entry("chromium", CHROMIUM_ID, "allow", "").replace("owner: bob", "owner: \"bo\u{3164}b\"");
    let reason = entry("chromium", CHROMIUM_ID, "allow", "").replace("reason: ok", "reason: \"o\u{202e}k\"");
    assert!(parse(&owner).is_err());
    assert!(parse(&reason).is_err());
    Ok(())
}


#[test]
fn unknown_field_is_refused() -> Result<(), Box<dyn Error>> {
    assert!(parse(&entry("chromium", CHROMIUM_ID, "allow", ", extra: 1")).is_err());
    assert!(parse("default: allow\nother: 1\n").is_err());
    Ok(())
}


#[test]
fn too_many_extensions_are_refused() -> Result<(), Box<dyn Error>> {
    let line = "  - {browser: firefox, id: a@e.org, action: allow, owner: bob, reason: ok}\n";
    let text = format!("default: allow\nextensions:\n{}", line.repeat(MAX_EXTENSIONS + 1));
    let error = parse(&text).err().ok_or("accepted")?;
    assert!(matches!(error, PolicyError::TooManyExtensions { count, .. } if count == MAX_EXTENSIONS + 1));
    Ok(())
}


#[test]
fn oversized_file_is_refused() -> Result<(), Box<dyn Error>> {
    let padding = "#".repeat(usize::try_from(MAX_POLICY_BYTES).unwrap_or(usize::MAX));
    assert!(parse(&format!("default: allow\n{padding}\n")).is_err());
    Ok(())
}
