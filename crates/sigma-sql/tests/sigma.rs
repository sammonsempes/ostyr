#[path = "support/types.rs"]
mod types;


use proptest::prelude::*;
use sigma_sql::cli::{run, run_reporting};
use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::condition::{tokenize, Quantifier, Token};
use sigma_sql::error::SigmaError;
use sigma_sql::mapping::{parse_mapping, FieldMapping};
use sigma_sql::modifier::{parse_field_key, Matcher};
use sigma_sql::rule::parse_rule;
use sigma_sql::sql::{like_escape, quote_identifier, sql_literal};
use sigma_sql::value::{like_pattern, parse_pieces, Piece};
use std::fs::{read_dir, read_to_string};
use std::io::{self, Write};
use std::process::ExitCode;
use types::TestResult;


const RULE_FILES: usize = 2;


const MIN_LITERALS: usize = 3;


const MAPPING_TEXT: &str = include_str!("../mappings/ecs.yaml");


fn mapping() -> Result<FieldMapping, SigmaError> {
    parse_mapping(MAPPING_TEXT)
}


fn compile(text: &str) -> Result<String, SigmaError> {
    compile_rule(text, &mapping()?, &SqlOptions::default())
}


fn windows_rule(detection: &str) -> String {
    format!("title: Test rule\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n{detection}\n")
}


fn with_condition(selection: &str, condition: &str) -> String {
    windows_rule(&format!("  selection:\n    {selection}\n  condition: {condition}"))
}


fn error_of(text: &str) -> Result<SigmaError, String> {
    match compile(text) {
        Ok(sql) => Err(format!("expected an error, got {sql}")),
        Err(error) => Ok(error),
    }
}


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}


#[test]
fn every_rule_matches_its_snapshot() -> TestResult {
    let mapping = mapping()?;
    let entries = read_dir("tests/rules")?.collect::<Result<Vec<_>, _>>()?;
    assert!(!entries.is_empty());
    entries.iter().try_for_each(|entry| -> TestResult {
        let path = entry.path();
        let stem = path.file_stem().and_then(|name| name.to_str()).ok_or("bad file name")?;
        let expected = read_to_string(format!("tests/snapshots/{stem}.sql"))?;
        let actual = compile_rule(&read_to_string(&path)?, &mapping, &SqlOptions::default())?;
        assert_eq!(format!("{actual}\n"), expected, "{stem}");
        Ok(())
    })
}


#[test]
fn rule_metadata_is_parsed() -> TestResult {
    let rule = parse_rule(&read_to_string("tests/rules/map_and.yml")?)?;
    assert_eq!(rule.title, "Selection map is an AND");
    assert_eq!(rule.id.as_deref(), Some("00000000-0000-4000-8000-000000000001"));
    assert_eq!(rule.status.as_deref(), Some("test"));
    assert_eq!(rule.level.as_deref(), Some("medium"));
    assert_eq!(rule.tags, vec!["attack.execution".to_string()]);
    assert_eq!(rule.condition, "selection");
    assert_eq!(rule.selections.len(), 1);
    let bare = parse_rule(&windows_rule("  selection:\n    Image: a\n  condition: selection"))?;
    assert!(bare.tags.is_empty());
    Ok(())
}


#[test]
fn metadata_keys_are_accepted() -> TestResult {
    let text = format!(
        "description: x\nauthor: y\n{}",
        windows_rule("  selection:\n    Image: a\n  condition: selection")
    );
    assert!(compile(&text).is_ok());
    Ok(())
}


#[test]
fn custom_options_pick_table_and_id_column() -> TestResult {
    let options = SqlOptions {
        table: "edr_events".to_string(),
        id_column: "id".to_string(),
    };
    let sql = compile_rule(&with_condition("Image: a", "selection"), &mapping()?, &options)?;
    assert!(sql.starts_with("SELECT `id` FROM `edr_events` WHERE "));
    Ok(())
}


#[test]
fn bad_identifiers_in_options_are_refused() -> TestResult {
    let bad_table = SqlOptions {
        table: "events; DROP".to_string(),
        id_column: "id".to_string(),
    };
    let bad_id = SqlOptions {
        table: "events".to_string(),
        id_column: "i`d".to_string(),
    };
    let text = with_condition("Image: a", "selection");
    assert!(matches!(compile_rule(&text, &mapping()?, &bad_table), Err(SigmaError::BadIdentifier(_))));
    assert!(matches!(compile_rule(&text, &mapping()?, &bad_id), Err(SigmaError::BadIdentifier(_))));
    Ok(())
}


#[test]
fn identifiers_are_validated() -> TestResult {
    assert_eq!(quote_identifier("event.id")?, "`event.id`");
    assert_eq!(quote_identifier("a_1")?, "`a_1`");
    assert!(quote_identifier("").is_err());
    assert!(quote_identifier("a b").is_err());
    assert!(quote_identifier("a`b").is_err());
    Ok(())
}


#[test]
fn literals_and_like_escapes() -> TestResult {
    assert_eq!(sql_literal("a'b\\c\nd\re\tf\0g"), "'a\\'b\\\\c\\nd\\re\\tf\\0g'");
    assert_eq!(like_escape('%'), "\\%");
    assert_eq!(like_escape('_'), "\\_");
    assert_eq!(like_escape('\\'), "\\\\");
    assert_eq!(like_escape('a'), "a");
    Ok(())
}


#[test]
fn pieces_follow_sigma_escaping() -> TestResult {
    assert_eq!(
        parse_pieces("a*b?"),
        vec![Piece::Literal('a'), Piece::Many, Piece::Literal('b'), Piece::One]
    );
    assert_eq!(parse_pieces("\\*"), vec![Piece::Literal('*')]);
    assert_eq!(parse_pieces("\\\\*"), vec![Piece::Literal('\\'), Piece::Many]);
    assert_eq!(parse_pieces("\\\\\\?"), vec![Piece::Literal('\\'), Piece::Literal('?')]);
    assert_eq!(parse_pieces("a\\b"), vec![Piece::Literal('a'), Piece::Literal('\\'), Piece::Literal('b')]);
    assert_eq!(parse_pieces("a\\"), vec![Piece::Literal('a'), Piece::Literal('\\')]);
    assert_eq!(like_pattern(&parse_pieces("a%_*"), true, true), "%a\\%\\_%%");
    assert_eq!(like_pattern(&parse_pieces("a"), false, false), "a");
    Ok(())
}


#[test]
fn modifiers_parse() -> TestResult {
    let (field, plain) = parse_field_key("r", "Image")?;
    assert_eq!(
        (field.as_str(), plain.matcher, plain.all, plain.windash),
        ("Image", Matcher::Equals, false, false)
    );
    let (_, chained) = parse_field_key("r", "CommandLine|windash|all|contains")?;
    assert_eq!((chained.matcher, chained.all, chained.windash), (Matcher::Contains, true, true));
    assert_eq!(parse_field_key("r", "A|startswith")?.1.matcher, Matcher::StartsWith);
    assert_eq!(parse_field_key("r", "A|endswith")?.1.matcher, Matcher::EndsWith);
    assert_eq!(parse_field_key("r", "A|re")?.1.matcher, Matcher::Regex);
    assert_eq!(parse_field_key("r", "A|cidr")?.1.matcher, Matcher::Cidr);
    assert_eq!(parse_field_key("r", "A|exists")?.1.matcher, Matcher::Exists);
    Ok(())
}


#[test]
fn modifier_errors() -> TestResult {
    assert!(matches!(parse_field_key("r", "A|base64"), Err(SigmaError::UnknownModifier { .. })));
    assert!(matches!(parse_field_key("r", "A|"), Err(SigmaError::UnknownModifier { .. })));
    assert!(matches!(parse_field_key("r", "A|all|all"), Err(SigmaError::UnknownModifier { .. })));
    assert!(matches!(
        parse_field_key("r", "A|windash|windash"),
        Err(SigmaError::UnknownModifier { .. })
    ));
    assert!(matches!(parse_field_key("r", "A|contains|endswith"), Err(SigmaError::Unsupported { .. })));
    assert!(matches!(parse_field_key("r", "A|windash|re"), Err(SigmaError::Unsupported { .. })));
    assert!(matches!(parse_field_key("r", "A|cidr|windash"), Err(SigmaError::Unsupported { .. })));
    assert!(matches!(parse_field_key("r", "|contains"), Err(SigmaError::Unsupported { .. })));
    Ok(())
}


#[test]
fn unknown_modifier_in_a_rule_names_rule_and_modifier() -> TestResult {
    let error = error_of(&with_condition("Image|rot13: a", "selection"))?;
    assert!(matches!(&error, SigmaError::UnknownModifier { rule, modifier, .. } if rule == "Test rule" && modifier == "rot13"));
    assert!(error.to_string().contains("Test rule"));
    Ok(())
}


#[test]
fn unmapped_field_is_an_error() -> TestResult {
    let error = error_of(&with_condition("Nonsense: a", "selection"))?;
    assert!(matches!(&error, SigmaError::UnmappedField { field, category, .. } if field == "Nonsense" && category == "process_creation"));
    Ok(())
}


#[test]
fn unsupported_constructs_are_refused() -> TestResult {
    let unsupported = [
        format!("action: global\n{}", with_condition("Image: a", "selection")),
        with_condition("Image: a", "selection | count() > 3"),
        windows_rule("  selection:\n    Image: a\n  timeframe: 5m\n  condition: selection"),
        windows_rule("  selection:\n    Image: a\n  condition:\n    - selection"),
        windows_rule("  selection:\n    - keyword\n  condition: selection"),
        windows_rule("  selection: keyword\n  condition: selection"),
        windows_rule("  selection: []\n  condition: selection"),
        windows_rule("  selection: {}\n  condition: selection"),
        with_condition("Image: []", "selection"),
        "title: T\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image: a\n  condition: selection\n".to_string(),
        "title: T\nlogsource:\n  category: registry_set\ndetection:\n  selection:\n    Image: a\n  condition: selection\n".to_string(),
        "title: T\nlogsource:\n  category: process_creation\n  service: security\ndetection:\n  selection:\n    Image: a\n  condition: selection\n"
            .to_string(),
        "title: T\nlogsource:\n  category: process_creation\n  product: macos\ndetection:\n  selection:\n    Image: a\n  condition: selection\n"
            .to_string(),
    ];
    unsupported.iter().try_for_each(|text| -> TestResult {
        let error = error_of(text)?;
        assert!(matches!(error, SigmaError::Unsupported { .. }), "{text}: {error}");
        Ok(())
    })
}


#[test]
fn missing_condition_is_a_bad_condition() -> TestResult {
    let error = error_of(&windows_rule("  selection:\n    Image: a"))?;
    assert!(matches!(error, SigmaError::BadCondition { .. }));
    Ok(())
}


#[test]
fn invalid_yaml_and_shape_are_yaml_errors() -> TestResult {
    assert!(matches!(error_of("title: [")?, SigmaError::Yaml(_)));
    assert!(matches!(error_of("title: T\n")?, SigmaError::Yaml(_)));
    assert!(matches!(
        error_of("title: T\nlogsource:\n  weird: 1\ndetection:\n  condition: a\n")?,
        SigmaError::Yaml(_)
    ));
    assert!(error_of("title: [")?.to_string().contains("YAML"));
    Ok(())
}


#[test]
fn bad_conditions_are_typed_errors() -> TestResult {
    let conditions = [
        "selection and",
        "and selection",
        "selection selection",
        "(selection",
        "selection)",
        "selection )",
        "()",
        "( )",
        "selection not selection",
        "selection (selection)",
        "1 of",
        "1 selection",
        "not",
        "selection or or selection",
        "((selection)",
        "1 of sel[",
    ];
    conditions.iter().try_for_each(|condition| -> TestResult {
        let error = error_of(&with_condition("Image: a", condition))?;
        assert!(matches!(error, SigmaError::BadCondition { .. }), "{condition}: {error}");
        Ok(())
    })
}


#[test]
fn empty_condition_is_a_bad_condition() -> TestResult {
    let error = error_of(&windows_rule("  selection:\n    Image: a\n  condition: ''"))?;
    assert!(matches!(error, SigmaError::BadCondition { .. }));
    Ok(())
}


#[test]
fn missing_selections_are_typed_errors() -> TestResult {
    let names = ["other", "selection and other", "1 of nothing*", "all of nothing*"];
    names.iter().try_for_each(|condition| -> TestResult {
        let error = error_of(&with_condition("Image: a", condition))?;
        assert!(matches!(error, SigmaError::MissingSelection { .. }), "{condition}: {error}");
        Ok(())
    })?;
    let no_selection = error_of(&windows_rule("  condition: 1 of them"))?;
    assert!(matches!(no_selection, SigmaError::MissingSelection { .. }));
    Ok(())
}


#[test]
fn bad_values_are_typed_errors() -> TestResult {
    let selections = [
        "CommandLine|re: '('",
        "Image|cidr: nocidr",
        "Image|cidr: x/8",
        "Image|cidr: 10.0.0.0/abc",
        "Image|cidr: 10.0.0.0/33",
        "Image|cidr: '::1/129'",
        "Image|exists: 1",
        "Image|contains: null",
        "Image:\n      nested: value",
        "Image: [[a]]",
        "Image|exists: text",
    ];
    selections.iter().try_for_each(|selection| -> TestResult {
        let error = error_of(&with_condition(selection, "selection"))?;
        assert!(matches!(error, SigmaError::BadValue { .. }), "{selection}: {error}");
        Ok(())
    })
}


#[test]
fn cidr_bounds_are_accepted() -> TestResult {
    let sql = compile(&with_condition("Image|cidr: 192.168.0.0/32", "selection"))?;
    assert!(sql.contains("isIPAddressInRange(toString(`process.executable`), '192.168.0.0/32')"));
    let v6 = compile(&with_condition("Image|cidr: '::1/128'", "selection"))?;
    assert!(v6.contains("'::1/128'"));
    Ok(())
}


#[test]
fn condition_tokens() -> TestResult {
    let tokens = tokenize("r", "(a and not b) or 1 of c* and all of them")?;
    assert_eq!(
        tokens,
        vec![
            Token::Open,
            Token::Selection("a".to_string()),
            Token::And,
            Token::Not,
            Token::Selection("b".to_string()),
            Token::Close,
            Token::Or,
            Token::Of(Quantifier::One, "c*".to_string()),
            Token::And,
            Token::Of(Quantifier::All, "them".to_string()),
        ]
    );
    Ok(())
}


#[test]
fn precedence_is_not_then_and_then_or() -> TestResult {
    let text = windows_rule("  a:\n    Image: a\n  b:\n    Image: b\n  c:\n    Image: c\n  condition: a or b and not c");
    let sql = compile(&text)?;
    assert!(sql.ends_with("AND ((`process.executable` ilike 'a') OR ((`process.executable` ilike 'b') AND NOT (`process.executable` ilike 'c')))"));
    Ok(())
}


#[test]
fn mapping_errors() -> TestResult {
    assert!(matches!(parse_mapping("products: ["), Err(SigmaError::Yaml(_))));
    assert!(matches!(
        parse_mapping("products: {}\ncategories: {}\nextra: 1\n"),
        Err(SigmaError::Yaml(_))
    ));
    let bad_column = "products: {}\ncategories:\n  c:\n    event_category: process\n    fields:\n      A: 'x y'\n";
    assert!(matches!(parse_mapping(bad_column), Err(SigmaError::BadIdentifier(_))));
    Ok(())
}


#[test]
fn cli_writes_one_line_per_rule() -> TestResult {
    let mut out = Vec::new();
    run(
        &["mappings/ecs.yaml", "events", "tests/rules/map_and.yml", "tests/rules/regex.yml"],
        &mut out,
    )?;
    let text = String::from_utf8(out)?;
    assert_eq!(text.lines().count(), RULE_FILES);
    assert!(text.starts_with("SELECT `event.id` FROM `events` WHERE "));
    Ok(())
}


#[test]
fn cli_errors() -> TestResult {
    let mut out = Vec::new();
    assert!(matches!(run(&[], &mut out), Err(SigmaError::Usage)));
    assert!(matches!(run(&["mappings/ecs.yaml", "events"], &mut out), Err(SigmaError::Usage)));
    assert!(matches!(
        run(&["missing.yaml", "events", "tests/rules/regex.yml"], &mut out),
        Err(SigmaError::Read { .. })
    ));
    assert!(matches!(
        run(&["mappings/ecs.yaml", "events", "missing.yml"], &mut out),
        Err(SigmaError::Read { .. })
    ));
    assert!(matches!(
        run(&["tests/rules/regex.yml", "events", "tests/rules/regex.yml"], &mut out),
        Err(SigmaError::Yaml(_))
    ));
    assert!(matches!(
        run(&["mappings/ecs.yaml", "bad table", "tests/rules/regex.yml"], &mut out),
        Err(SigmaError::BadIdentifier(_))
    ));
    let mut failing = FailingWriter;
    assert!(matches!(
        run(&["mappings/ecs.yaml", "events", "tests/rules/regex.yml"], &mut failing),
        Err(SigmaError::Output(_))
    ));
    assert!(failing.flush().is_err());
    let read_error = run(&["missing.yaml", "events", "x"], &mut out).err().ok_or("expected an error")?;
    assert!(read_error.to_string().contains("missing.yaml"));
    Ok(())
}


#[test]
fn cli_reporting_maps_outcomes_to_exit_codes() -> TestResult {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let success = run_reporting(&["mappings/ecs.yaml", "events", "tests/rules/regex.yml"], &mut out, &mut err)?;
    assert_eq!(format!("{success:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(err.is_empty());
    let failure = run_reporting(&[], &mut out, &mut err)?;
    assert_eq!(format!("{failure:?}"), format!("{:?}", ExitCode::FAILURE));
    assert!(String::from_utf8(err)?.contains("usage"));
    assert!(run_reporting(&[], &mut Vec::new(), &mut FailingWriter).is_err());
    Ok(())
}


fn literal_stays_closed(literal: &str) -> bool {
    let body = literal.strip_prefix('\'').and_then(|rest| rest.strip_suffix('\''));
    body.is_some_and(|text| {
        let (escaped, intact) = text
            .chars()
            .fold((false, true), |(escaped, intact), character| match (escaped, character) {
                (true, _) => (false, intact),
                (false, '\\') => (true, intact),
                (false, '\'') => (false, false),
                (false, _) => (false, intact),
            });
        intact && !escaped
    })
}


fn closed_literal_count(sql: &str) -> Option<usize> {
    let (inside, escaped, count) = sql.chars().fold((false, false, 0), |(inside, escaped, count), character| {
        match (inside, escaped, character) {
            (true, true, _) => (true, false, count),
            (true, false, '\\') => (true, true, count),
            (true, false, '\'') => (false, false, count),
            (true, false, _) => (true, false, count),
            (false, _, '\'') => (true, false, count + 1),
            (false, _, _) => (false, false, count),
        }
    });
    if inside || escaped {
        None
    } else {
        Some(count)
    }
}


proptest! {
    #[test]
    fn no_value_closes_a_literal(value in "\\PC{0,40}") {
        prop_assert!(literal_stays_closed(&sql_literal(&value)));
    }

    #[test]
    fn no_rule_value_escapes_its_literal(value in "[ -~\\t]{0,40}", modifier in prop::sample::select(vec!["", "|contains", "|startswith", "|endswith", "|re", "|windash|contains"])) {
        let quoted = serde_json::to_string(&value).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let text = with_condition(&format!("Image{modifier}: {quoted}"), "selection");
        if let Ok(sql) = compile(&text) {
            prop_assert!(closed_literal_count(&sql).is_some_and(|count| count >= MIN_LITERALS), "{}", sql);
        }
    }

    #[test]
    fn like_patterns_never_leak_wildcards(value in "[a-z%_\\\\]{1,12}") {
        let pattern = like_pattern(&value.chars().map(Piece::Literal).collect::<Vec<_>>(), false, false);
        let unescaped = pattern.replace("\\\\", "").replace("\\%", "").replace("\\_", "");
        prop_assert!(!unescaped.contains('%') && !unescaped.contains('_') && !unescaped.contains('\\'));
    }
}


fn security_rule(detection: &str) -> String {
    format!("title: T\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    {detection}\n  condition: selection\n")
}


#[test]
fn security_service_goldens() -> TestResult {
    let provider = "`host.os.type` = 'windows' AND `event.provider` = 'Microsoft-Windows-Security-Auditing'";
    assert_eq!(
        compile(&read_to_string("tests/rules/winsec_4625.yml")?)?,
        format!("SELECT `event.id` FROM `events` WHERE {provider} AND ((`event.code` ilike '4625' AND `user.name` ilike '%admin'))")
    );
    assert_eq!(
        compile(&read_to_string("tests/rules/winsec_list.yml")?)?,
        format!("SELECT `event.id` FROM `events` WHERE {provider} AND ((`event.code` ilike '4624' OR `event.code` ilike '4625'))")
    );
    assert_eq!(
        compile(&security_rule("SubjectUserName: \"O'Brien\""))?,
        format!("SELECT `event.id` FROM `events` WHERE {provider} AND (`user.name` ilike 'O\\'Brien')")
    );
    Ok(())
}


#[test]
fn security_service_refuses_label_fields_and_bad_ids() -> TestResult {
    let error = error_of(&security_rule("LogonType: 3"))?;
    assert!(
        matches!(&error, SigmaError::UnmappedField { field, .. } if field == "LogonType"),
        "{error}"
    );
    assert!(error.to_string().contains("LogonType"));
    ["EventID: 4.5", "EventID: true", "EventID: null", "EventID: [4624, 4.5]"]
        .iter()
        .try_for_each(|detection| -> TestResult {
            let refused = error_of(&security_rule(detection))?;
            assert!(matches!(refused, SigmaError::BadValue { .. }), "{detection}: {refused}");
            Ok(())
        })
}


#[test]
fn security_service_refuses_bad_logsources() -> TestResult {
    let both =
        "title: T\nlogsource:\n  category: process_creation\n  service: security\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    let unknown = "title: T\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    let neither = "title: T\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    [both, unknown, neither].iter().try_for_each(|text| -> TestResult {
        let error = error_of(text)?;
        assert!(matches!(error, SigmaError::Unsupported { .. }), "{text}: {error}");
        Ok(())
    })
}


#[test]
fn service_columns_are_checked_as_identifiers() -> TestResult {
    let bad = "products: {}\ncategories: {}\nservices:\n  s:\n    provider: p\n    fields:\n      A: 'x y'\n";
    assert!(matches!(parse_mapping(bad), Err(SigmaError::BadIdentifier(_))));
    Ok(())
}


#[test]
fn security_event_id_text_is_kept_as_written() -> TestResult {
    let sql = compile(&security_rule("EventID|startswith: '46'"))?;
    assert!(sql.ends_with("AND (`event.code` ilike '46%')"), "{sql}");
    Ok(())
}
