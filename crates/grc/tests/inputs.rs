#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use grc::error::GrcError;
use grc::inputs::{load_indicators, load_manual, parse_indicators, parse_manual, MAX_INDICATORS, MAX_INPUT_BYTES, MAX_MANUAL};
use std::io::Read;
use types::TestResult;


const INDICATOR_COUNT: usize = 2;


const INDICATORS: &str = r#"[
  {"tenant":"acme","name":"edr.share","value":93.5,"observed_at":"2026-11-12T10:00:00Z","source":"edr"},
  {"tenant":"acme","name":"backup.age_hours","value":4,"observed_at":"2026-11-12T09:00:00+01:00","source":"backup"}
]"#;


const MANUAL: &str = "evidence:
  - tenant: acme
    control: A.5.1
    owner: ciso
    recorded_at: 2026-11-01T08:00:00Z
    review_until: 2027-11-01T08:00:00Z
";


const MANUAL_RECORD: &str =
    "  - tenant: acme\n    control: A.5.1\n    owner: ciso\n    recorded_at: 2026-11-01T08:00:00Z\n    review_until: 2027-11-01T08:00:00Z\n";


fn indicator_json(name: &str, source: &str) -> String {
    format!(r#"[{{"tenant":"acme","name":"{name}","value":1,"observed_at":"2026-11-12T10:00:00Z","source":"{source}"}}]"#)
}


#[test]
fn indicators_parse() -> TestResult {
    let values = parse_indicators(&mut INDICATORS.as_bytes(), "i.json")?;
    assert_eq!(values.len(), INDICATOR_COUNT);
    assert_eq!(values.first().ok_or("none")?.tenant, "acme");
    Ok(())
}


#[test]
fn a_number_out_of_range_is_refused() -> TestResult {
    let text = INDICATORS.replace("93.5", "1e309");
    assert!(matches!(parse_indicators(&mut text.as_bytes(), "i.json"), Err(GrcError::Json { .. })));
    Ok(())
}


#[test]
fn malformed_indicators_are_refused() -> TestResult {
    for text in ["{}", "[{\"tenant\":\"acme\"}]", "not json"] {
        assert!(matches!(parse_indicators(&mut text.as_bytes(), "i.json"), Err(GrcError::Json { .. })));
    }
    let unknown = INDICATORS.replace("\"source\"", "\"extra\":1,\"source\"");
    assert!(parse_indicators(&mut unknown.as_bytes(), "i.json").is_err());
    let string_value = INDICATORS.replace("93.5", "\"93.5\"");
    assert!(parse_indicators(&mut string_value.as_bytes(), "i.json").is_err());
    Ok(())
}


#[test]
fn an_indicator_name_or_source_outside_the_grammar_is_refused() -> TestResult {
    for text in [
        indicator_json("-bad", "edr"),
        indicator_json("a\\u202eb", "edr"),
        indicator_json("ok", "bad\\u202esource"),
        indicator_json("ok", ""),
    ] {
        assert!(
            matches!(parse_indicators(&mut text.as_bytes(), "i.json"), Err(GrcError::Invalid { .. })),
            "{text}"
        );
    }
    Ok(())
}


#[test]
fn the_indicator_count_is_capped() -> TestResult {
    let one = indicator_json("a", "s");
    let inner = one.trim_start_matches('[').trim_end_matches(']').to_owned();
    let build = |count: usize| format!("[{}]", vec![inner.as_str(); count].join(","));
    assert_eq!(parse_indicators(&mut build(MAX_INDICATORS).as_bytes(), "i.json")?.len(), MAX_INDICATORS);
    assert!(matches!(
        parse_indicators(&mut build(MAX_INDICATORS + 1).as_bytes(), "i.json"),
        Err(GrcError::Invalid { .. })
    ));
    Ok(())
}


#[test]
fn an_oversized_indicator_file_is_refused() -> TestResult {
    let mut endless = std::io::repeat(b'a').take(MAX_INPUT_BYTES + 1);
    assert!(matches!(
        parse_indicators(&mut endless, "i.json"),
        Err(GrcError::Config(ConfigError::TooLarge { .. }))
    ));
    Ok(())
}


#[test]
fn manual_evidence_parses() -> TestResult {
    let records = parse_manual(&mut MANUAL.as_bytes(), "m.yaml")?;
    let record = records.first().ok_or("none")?;
    assert_eq!(record.control, "A.5.1");
    assert_eq!(record.owner, "ciso");
    Ok(())
}


#[test]
fn malformed_manual_evidence_is_refused() -> TestResult {
    assert!(parse_manual(&mut "evidence: nope\n".as_bytes(), "m.yaml").is_err());
    let unknown = MANUAL.replace("owner: ciso", "owner: ciso\n    extra: 1");
    assert!(parse_manual(&mut unknown.as_bytes(), "m.yaml").is_err());
    let bad_date = MANUAL.replace("2027-11-01T08:00:00Z", "tomorrow");
    assert!(parse_manual(&mut bad_date.as_bytes(), "m.yaml").is_err());
    let missing_owner = MANUAL.replace("    owner: ciso\n", "");
    assert!(parse_manual(&mut missing_owner.as_bytes(), "m.yaml").is_err());
    Ok(())
}


#[test]
fn a_manual_control_or_owner_outside_the_grammar_is_refused() -> TestResult {
    for text in [
        MANUAL.replace("A.5.1", "-x"),
        MANUAL.replace("owner: ciso", "owner: \"a\\u202Eb\""),
        MANUAL.replace("owner: ciso", "owner: \" \""),
        MANUAL.replace("owner: ciso", "owner: Alice"),
        MANUAL.replace("owner: ciso", "owner: \"alice\\u3164\""),
        MANUAL.replace("owner: ciso", "owner: \"-x\""),
        MANUAL.replace("owner: ciso", "owner: \"\""),
    ] {
        assert!(
            matches!(parse_manual(&mut text.as_bytes(), "m.yaml"), Err(GrcError::Invalid { .. })),
            "{text}"
        );
    }
    Ok(())
}


#[test]
fn the_manual_record_count_is_capped() -> TestResult {
    let build = |count: usize| format!("evidence:\n{}", MANUAL_RECORD.repeat(count));
    assert_eq!(parse_manual(&mut build(MAX_MANUAL).as_bytes(), "m.yaml")?.len(), MAX_MANUAL);
    assert!(matches!(
        parse_manual(&mut build(MAX_MANUAL + 1).as_bytes(), "m.yaml"),
        Err(GrcError::Invalid { .. })
    ));
    Ok(())
}


#[test]
fn inputs_load_from_paths_and_missing_paths_fail() -> TestResult {
    let directory = tempfile::tempdir()?;
    let indicators = directory.path().join("i.json");
    let manual = directory.path().join("m.yaml");
    std::fs::write(&indicators, INDICATORS)?;
    std::fs::write(&manual, MANUAL)?;
    assert_eq!(load_indicators(&indicators)?.len(), INDICATOR_COUNT);
    assert_eq!(load_manual(&manual)?.len(), 1);
    assert!(matches!(
        load_indicators(&directory.path().join("x")),
        Err(GrcError::Config(ConfigError::Io { .. }))
    ));
    assert!(matches!(
        load_manual(&directory.path().join("x")),
        Err(GrcError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


const LONG_KEY_CHARS: usize = 1_000_000;


const LONG_VALUE_CHARS: usize = 3_000_000;


const MAX_ERROR_CHARS: usize = 200;


fn error_chain(error: &GrcError) -> String {
    let first: Option<&dyn std::error::Error> = Some(error);
    std::iter::successors(first, |level| level.source())
        .map(|level| level.to_string())
        .collect()
}


#[test]
fn a_json_error_carries_no_input_text() -> TestResult {
    let bidi_key = "\u{202e}evil\u{1b}[31m";
    let long_key = "k".repeat(LONG_KEY_CHARS);
    let long_value = "v".repeat(LONG_VALUE_CHARS);
    let cases = [
        (format!(r#"[{{"{bidi_key}":1,"tenant":"acme"}}]"#), vec!["evil", "\u{202e}", "\u{1b}"]),
        (format!(r#"[{{"{long_key}":1}}]"#), vec!["kkkkkkkk"]),
        (
            format!(r#"[{{"tenant":"acme","name":"a","value":"{long_value}","observed_at":"x","source":"s"}}]"#),
            vec!["vvvvvvvv"],
        ),
    ];
    for (text, forbidden) in &cases {
        let error = parse_indicators(&mut text.as_bytes(), "i.json").err().ok_or("accepted")?;
        let chain = error_chain(&error);
        assert!(matches!(error, GrcError::Json { .. }));
        assert!(chain.chars().count() < MAX_ERROR_CHARS, "{chain}");
        assert!(forbidden.iter().all(|piece| !chain.contains(piece)));
    }
    Ok(())
}
