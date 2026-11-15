use core_config::error::ConfigError;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{repeat, Read};
use waf::error::WafError;
use waf::limits::{MAX_FILE_BYTES, MAX_ROUTES};
use waf::model::Refusal;
use waf::render::{render_reader, render_text};
use waf::validate::{BAD_HOST, MALFORMED};


const GOLDEN_YAML: &str = "tests/fixtures/two_routes.yaml";


const GOLDEN_JSON: &str = "tests/fixtures/two_routes.json";


const FIRST_ROUTE: usize = 0;


const EXTRA: usize = 1;


const NOT_A_LIST: u8 = 3;


fn good_route() -> Value {
    json!({"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]})
}


#[test]
fn two_routes_match_the_golden_json() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&fs::read_to_string(GOLDEN_YAML)?)?;
    let produced: Value = serde_json::to_value(&rendered.config)?;
    let expected: Value = serde_json::from_str(&fs::read_to_string(GOLDEN_JSON)?)?;
    assert_eq!(produced, expected);
    assert!(rendered.refused.is_empty());
    Ok(())
}


#[test]
fn hostile_routes_are_refused_and_the_rest_stays_valid() -> Result<(), Box<dyn Error>> {
    let hostile = ["a\"b.test", "a}.test", "a\nb.test", "a\u{0}b.test", "a{b}.test"];
    let routes: Vec<Value> = hostile
        .iter()
        .map(|host| json!({"hosts": [host], "backends": ["127.0.0.1:9001"]}))
        .chain(std::iter::once(good_route()))
        .collect();
    let rendered = render_text(&json!({ "routes": routes }).to_string())?;
    let encoded = serde_json::to_string(&rendered.config)?;
    let reparsed: Value = serde_json::from_str(&encoded)?;
    assert_eq!(
        reparsed.pointer("/apps/http/servers/main/routes").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    assert_eq!(rendered.refused.len(), hostile.len());
    assert!(rendered.refused.iter().all(|refusal| refusal.reason == BAD_HOST));
    assert!(!encoded.contains('\u{0}'));
    Ok(())
}


#[test]
fn a_malformed_route_refuses_only_itself() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&json!({"routes": [good_route(), {"hosts": NOT_A_LIST}]}).to_string())?;
    assert_eq!(
        rendered.refused,
        [Refusal {
            index: EXTRA,
            reason: MALFORMED
        }]
    );
    assert_eq!(
        rendered
            .config
            .apps
            .http
            .servers
            .values()
            .map(|server| server.routes.len())
            .sum::<usize>(),
        EXTRA
    );
    Ok(())
}


#[test]
fn the_limit_of_routes_is_accepted_and_one_more_is_refused() -> Result<(), Box<dyn Error>> {
    let at_limit = render_text(&json!({"routes": vec![json!({}); MAX_ROUTES]}).to_string())?;
    assert_eq!(at_limit.refused.len(), MAX_ROUTES);
    assert_eq!(at_limit.refused.first().map(|refusal| refusal.index), Some(FIRST_ROUTE));
    let over = render_text(&json!({"routes": vec![json!({}); MAX_ROUTES + EXTRA]}).to_string());
    assert!(matches!(over, Err(WafError::TooManyRoutes { count, max }) if count == MAX_ROUTES + EXTRA && max == MAX_ROUTES));
    Ok(())
}


#[test]
fn a_file_over_the_size_limit_is_refused() -> Result<(), Box<dyn Error>> {
    let over = render_reader(&mut Read::take(repeat(b' '), MAX_FILE_BYTES + 1));
    assert!(matches!(over, Err(WafError::Config(ConfigError::TooLarge { .. }))));
    Ok(())
}


#[test]
fn a_file_at_the_size_limit_is_read() -> Result<(), Box<dyn Error>> {
    let mut text = String::from("routes: []");
    text.push_str(&" ".repeat(usize::try_from(MAX_FILE_BYTES)? - text.len()));
    let rendered = render_reader(&mut text.as_bytes())?;
    assert!(rendered.refused.is_empty());
    Ok(())
}


#[test]
fn bad_documents_are_refused_without_their_text() -> Result<(), Box<dyn Error>> {
    ["routes: [", "other: 1", "routes: 5", "- 1"].iter().for_each(|text| {
        let error = render_text(text).err().map(|failure| failure.to_string());
        assert!(error.is_some_and(|shown| shown.starts_with("routes:")), "{text}");
    });
    Ok(())
}
