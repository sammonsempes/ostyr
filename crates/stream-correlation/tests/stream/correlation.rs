use crate::support::{ruleset, ANY_ORDER, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS, DOWNLOAD, DROPPER, EXECUTE, LOGIN};
use crate::types::TestResult;
use stream_correlation::correlation::{parse_timespan, CorrelationRule, Kind};
use stream_correlation::error::CorrelationError;
use stream_correlation::ruleset::split_documents;
use stream_correlation::window::{holds, Hit};


const BASE_COUNT: usize = 4;


const ORDERED_POSITION: usize = 2;


const TEMPORAL_POSITION: usize = 3;


const THIRTY_SECONDS_MS: i64 = 30 * 1000;


const TWO_HOURS_MS: i64 = 2 * 60 * MILLIS_PER_MINUTE;


const ONE_DAY_MS: i64 = 24 * 60 * MILLIS_PER_MINUTE;


const DOCUMENT_COUNT: usize = 2;


const MILLIS_PER_MINUTE: i64 = 60_000;


const FIVE_MINUTES: i64 = 5 * MILLIS_PER_MINUTE;


const MILLIS_PER_WEEK: i64 = 7 * 24 * 60 * MILLIS_PER_MINUTE;


const OVERFLOWING_WEEKS: &str = "99999999999999999w";


fn correlation(extra: &str) -> String {
    format!("title: Variant\nid: variant\n{extra}")
}


fn failure(documents: &[&str]) -> Result<CorrelationError, Box<dyn std::error::Error>> {
    match ruleset(documents) {
        Ok(_) => Err("the rules were accepted".into()),
        Err(error) => Ok(error),
    }
}


fn inner(error: &CorrelationError) -> &CorrelationError {
    match error {
        CorrelationError::InFile { source, .. } => source,
        other => other,
    }
}


fn variant_failure(correlation_body: &str) -> Result<String, Box<dyn std::error::Error>> {
    let text = correlation(correlation_body);
    Ok(failure(&[LOGIN, &text])?.to_string())
}


#[test]
fn every_type_parses() -> TestResult {
    let rules = ruleset(&[LOGIN, BEACON, DOWNLOAD, EXECUTE, BRUTE_FORCE, DISTINCT_DESTINATIONS, DROPPER, ANY_ORDER])?;
    assert_eq!(rules.bases.len(), BASE_COUNT);
    let kinds: Vec<&Kind> = rules.correlations.iter().map(|rule| &rule.kind).collect();
    assert!(matches!(kinds.first(), Some(Kind::EventCount(_))));
    assert!(matches!(kinds.get(1), Some(Kind::ValueCount { .. })));
    assert!(matches!(kinds.get(ORDERED_POSITION), Some(Kind::TemporalOrdered)));
    assert!(matches!(kinds.get(TEMPORAL_POSITION), Some(Kind::Temporal)));
    let brute = rules.correlations.first().ok_or("no rule")?;
    assert_eq!(brute.timespan_ms, FIVE_MINUTES);
    assert_eq!(brute.group_by, vec!["host.name".to_string()]);
    assert!(!brute.generate);
    Ok(())
}


#[test]
fn rules_without_ids_fall_back_to_name_then_title() -> TestResult {
    let named = "title: Named\nname: by-name\ncorrelation:\n  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n";
    let titled = "title: Titled\nlevel: high\ndescription: metadata is accepted\ncorrelation:\n  type: temporal\n  rules: [failed-login]\n  generate: true\n  timespan: 1m\n";
    let rules = ruleset(&[LOGIN, named, titled])?;
    let ids: Vec<&str> = rules.correlations.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(ids, vec!["by-name", "Titled"]);
    assert!(rules.correlations.get(1).ok_or("no rule")?.generate);
    Ok(())
}


#[test]
fn timespans_parse_every_unit() -> TestResult {
    assert_eq!(parse_timespan("r", "30s")?, THIRTY_SECONDS_MS);
    assert_eq!(parse_timespan("r", "5m")?, FIVE_MINUTES);
    assert_eq!(parse_timespan("r", "2h")?, TWO_HOURS_MS);
    assert_eq!(parse_timespan("r", "1d")?, ONE_DAY_MS);
    assert_eq!(parse_timespan("r", "1w")?, MILLIS_PER_WEEK);
    for bad in ["5", "m", "0m", "-1m", "xm", "5y", OVERFLOWING_WEEKS] {
        assert!(matches!(parse_timespan("r", bad), Err(CorrelationError::Invalid { .. })), "{bad}");
    }
    Ok(())
}


#[test]
fn documents_split_on_separator_lines() -> TestResult {
    assert_eq!(split_documents("a: 1\n---\n\n---\nb: 2\n").len(), DOCUMENT_COUNT);
    assert_eq!(split_documents("---\na: 1\n").len(), 1);
    assert!(split_documents("\n").is_empty());
    Ok(())
}


#[test]
fn unsupported_constructs_name_the_rule() -> TestResult {
    let unknown_type = variant_failure("correlation:\n  type: sequence\n  rules: [failed-login]\n  timespan: 1m\n")?;
    assert!(unknown_type.contains("Variant") && unknown_type.contains("sequence"), "{unknown_type}");
    let extra_key = variant_failure("action: global\ncorrelation:\n  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n")?;
    assert!(extra_key.contains("top-level key action") && extra_key.contains("Variant"), "{extra_key}");
    let aliases = variant_failure("correlation:\n  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n  aliases: {}\n")?;
    assert!(aliases.contains("Variant") && aliases.contains("aliases"), "{aliases}");
    let temporal_condition = variant_failure("correlation:\n  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n  condition:\n    gte: 2\n")?;
    assert!(temporal_condition.contains("condition on a temporal rule"), "{temporal_condition}");
    let ordered_condition =
        variant_failure("correlation:\n  type: temporal_ordered\n  rules: [failed-login]\n  timespan: 1m\n  condition:\n    gte: 2\n")?;
    assert!(ordered_condition.contains("condition on a temporal rule"), "{ordered_condition}");
    Ok(())
}


#[test]
fn invalid_conditions_are_refused() -> TestResult {
    let head = "correlation:\n  type: event_count\n  rules: [failed-login]\n  timespan: 1m\n";
    let value_head = "correlation:\n  type: value_count\n  rules: [failed-login]\n  timespan: 1m\n";
    let missing = variant_failure(head)?;
    assert!(missing.contains("needs a condition"), "{missing}");
    let unknown_key = variant_failure(&format!("{head}  condition:\n    over: 3\n"))?;
    assert!(unknown_key.contains("condition key over"), "{unknown_key}");
    let two = variant_failure(&format!("{head}  condition:\n    gt: 3\n    lt: 9\n"))?;
    assert!(two.contains("exactly one"), "{two}");
    let none = variant_failure(&format!("{head}  condition: {{}}\n"))?;
    assert!(none.contains("exactly one"), "{none}");
    let negative = variant_failure(&format!("{head}  condition:\n    gte: -1\n"))?;
    assert!(negative.contains("non-negative integer"), "{negative}");
    let with_field = variant_failure(&format!("{head}  condition:\n    gte: 1\n    field: host.name\n"))?;
    assert!(with_field.contains("field in an event_count"), "{with_field}");
    let no_field = variant_failure(&format!("{value_head}  condition:\n    gte: 1\n"))?;
    assert!(no_field.contains("needs a string field"), "{no_field}");
    let bad_field = variant_failure(&format!("{value_head}  condition:\n    gte: 1\n    field: [a]\n"))?;
    assert!(bad_field.contains("needs a string field"), "{bad_field}");
    Ok(())
}


#[test]
fn invalid_references_and_structure_are_refused() -> TestResult {
    let unknown = variant_failure("correlation:\n  type: temporal\n  rules: [nothing]\n  timespan: 1m\n")?;
    assert!(unknown.contains("unknown rule reference nothing"), "{unknown}");
    let empty = variant_failure("correlation:\n  type: temporal\n  rules: []\n  timespan: 1m\n")?;
    assert!(empty.contains("at least one rule"), "{empty}");
    let bad_span = variant_failure("correlation:\n  type: temporal\n  rules: [failed-login]\n  timespan: soon\n")?;
    assert!(bad_span.contains("timespan"), "{bad_span}");
    let no_span = variant_failure("correlation:\n  type: temporal\n  rules: [failed-login]\n")?;
    assert!(no_span.contains("Variant"), "{no_span}");
    let untitled = failure(&[LOGIN, "id: x\ncorrelation:\n  type: temporal\n  rules: [failed-login]\n  timespan: 1m\n"])?;
    assert!(untitled.to_string().contains("untitled"), "{untitled}");
    Ok(())
}


#[test]
fn duplicate_identifiers_are_refused() -> TestResult {
    let twin = LOGIN.replace("title: Failed login", "title: Other");
    assert!(matches!(inner(&failure(&[LOGIN, &twin])?), CorrelationError::Duplicate(_)));
    let same_name = LOGIN.replace("id: failed-login", "id: failed_login");
    ruleset(&[&same_name])?;
    assert!(matches!(failure(&[LOGIN, BRUTE_FORCE, BRUTE_FORCE])?, CorrelationError::Duplicate(_)));
    Ok(())
}


#[test]
fn broken_documents_name_their_file() -> TestResult {
    let error = failure(&[LOGIN, "title: [unclosed"])?;
    assert!(matches!(&error, CorrelationError::InFile { file, .. } if file == "rules.yml"), "{error}");
    let bad_base = failure(&["title: X\nlogsource:\n  category: process_creation\ndetection:\n  condition: nothing\n"])?;
    assert!(bad_base.to_string().starts_with("rules.yml:"), "{bad_base}");
    Ok(())
}


fn ordered_rule() -> Result<CorrelationRule, Box<dyn std::error::Error>> {
    let rules = ruleset(&[LOGIN, DOWNLOAD, EXECUTE, DROPPER])?;
    Ok(rules.correlations.first().ok_or("no rule")?.clone())
}


fn hit(positions: &[usize]) -> Hit {
    Hit {
        timestamp_ms: 0,
        event_id: "e".to_string(),
        rules: positions.to_vec(),
        value: None,
    }
}


#[test]
fn ordered_progress_stops_once_every_rule_is_seen() -> TestResult {
    let rule = ordered_rule()?;
    assert!(holds(&rule, &[hit(&[0]), hit(&[1]), hit(&[1])]));
    assert!(!holds(&rule, &[hit(&[1]), hit(&[0])]));
    assert!(!holds(&rule, &[hit(&[0])]));
    Ok(())
}
