use core_config::error::ConfigError;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{repeat, Read};
use waf::cli::render_to;
use waf::error::WafError;
use waf::limits::{
    CATCH_ALL_UPSTREAMS, MAX_BACKENDS, MAX_FILE_BYTES, MAX_HOSTS, MAX_JSON_BYTES, MAX_LABEL_BYTES, MAX_PATHS, MAX_PATH_BYTES, MAX_RENDERED_UPSTREAMS,
    MAX_ROUTES, MIN_INTERVAL_SECONDS,
};
use waf::model::{Budget, Refusal, Rendered};
use waf::order::{TOO_MANY_BYTES, TOO_MANY_RENDERED};
use waf::render::{render_reader, render_text, render_text_capped};
use waf::validate::{BAD_HOST, MALFORMED, REPEATED_HOST};


const GOLDEN_YAML: &str = "tests/fixtures/two_routes.yaml";


const GOLDEN_JSON: &str = "tests/fixtures/two_routes.json";


const FIRST_ROUTE: usize = 0;


const EXTRA: usize = 1;


const SECOND: usize = 1;


const THIRD: usize = 2;


const FOURTH: usize = 3;


const FOUR_ROUTES: usize = 4;


const THREE_ROUTES: usize = 3;


const MAX_ROUTES_WITH_16_BACKENDS: usize = 125;


const LAST_LABEL_BYTES: usize = 60;


const PATH_PADDING: usize = 8;


const ROUTES_IN_LARGEST_FILE: usize = 100;


const BACKEND_LABEL_BYTES: usize = 60;


const THREE_KEYS: usize = 3;


const FIVE_KEYS: usize = 5;


const ROUTES_WITH_CATCH_ALL: usize = 2;


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
        Some(ROUTES_WITH_CATCH_ALL)
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
            reason: MALFORMED,
            shadowed_by: None
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
        EXTRA + EXTRA
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


fn assert_no_repeated_host(rendered: &waf::model::Rendered) -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_value(&rendered.config)?;
    let routes = value
        .pointer("/apps/http/servers/main/routes")
        .and_then(Value::as_array)
        .ok_or("no routes")?;
    routes.iter().for_each(|route| {
        let hosts: Vec<&str> = route
            .pointer("/match/0/host")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let distinct: std::collections::BTreeSet<&str> = hosts.iter().copied().collect();
        assert_eq!(distinct.len(), hosts.len());
    });
    Ok(())
}


#[test]
fn a_route_repeating_a_host_in_any_case_is_refused_alone() -> Result<(), Box<dyn Error>> {
    let text = json!({"routes": [
        {"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]},
        {"hosts": ["b.test", "B.test"], "backends": ["127.0.0.1:9002"]}
    ]})
    .to_string();
    let rendered = render_text(&text)?;
    assert_eq!(rendered.refused.len(), 1);
    assert_eq!(
        rendered.refused.first().map(|refusal| (refusal.index, refusal.reason)),
        Some((1, REPEATED_HOST))
    );
    assert_no_repeated_host(&rendered)?;
    assert!(!serde_json::to_string(&rendered.config)?.contains("b.test"));
    Ok(())
}


#[test]
fn the_golden_output_never_repeats_a_host() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&fs::read_to_string(GOLDEN_YAML)?)?;
    assert_no_repeated_host(&rendered)?;
    Ok(())
}


fn distinct_host_routes(count: usize, paths: &[&str]) -> String {
    let routes: Vec<Value> = (0..count)
        .map(|i| json!({"hosts": [format!("h{i}.test")], "paths": paths, "backends": ["127.0.0.1:9001"]}))
        .collect();
    json!({"routes": routes}).to_string()
}


fn budget(upstreams: usize, bytes: usize) -> Budget {
    Budget { upstreams, bytes }
}


fn refusals(rendered: &Rendered) -> Vec<(usize, &str)> {
    rendered.refused.iter().map(|refusal| (refusal.index, refusal.reason)).collect()
}


fn document_bytes(rendered: &Rendered) -> Result<usize, Box<dyn Error>> {
    Ok(serde_json::to_vec_pretty(&rendered.config)?.len() + 1)
}


#[test]
fn routes_beyond_the_upstream_budget_are_refused_in_file_order() -> Result<(), Box<dyn Error>> {
    let rendered = render_text_capped(&distinct_host_routes(FOUR_ROUTES, &["/a", "/b"]), &budget(FIVE_KEYS, usize::MAX))?;
    assert_eq!(refusals(&rendered), vec![(THIRD, TOO_MANY_RENDERED), (FOURTH, TOO_MANY_RENDERED)]);
    let value = serde_json::to_value(&rendered.config)?;
    let count = value.pointer("/apps/http/servers/main/routes").and_then(Value::as_array).map(Vec::len);
    assert_eq!(count, Some(FIVE_KEYS));
    Ok(())
}


#[test]
fn once_the_budget_is_reached_a_later_smaller_route_is_refused_too() -> Result<(), Box<dyn Error>> {
    let text = json!({"routes": [
        {"hosts": ["a.test"], "paths": ["/a", "/b"], "backends": ["127.0.0.1:9001"]},
        {"hosts": ["b.test"], "paths": ["/a", "/b", "/c"], "backends": ["127.0.0.1:9001"]},
        {"hosts": ["c.test"], "backends": ["127.0.0.1:9001"]}
    ]})
    .to_string();
    let rendered = render_text_capped(&text, &budget(THREE_KEYS, usize::MAX))?;
    let refused: Vec<usize> = rendered.refused.iter().map(|refusal| refusal.index).collect();
    assert_eq!(refused, vec![SECOND, THIRD]);
    Ok(())
}


#[test]
fn backends_count_as_upstreams_not_only_path_keys() -> Result<(), Box<dyn Error>> {
    let text = json!({"routes": [
        {"hosts": ["a.test"], "paths": ["/a"], "backends": ["127.0.0.1:9001", "127.0.0.2:9001", "127.0.0.3:9001", "127.0.0.4:9001"]},
        {"hosts": ["b.test"], "paths": ["/a"], "backends": ["127.0.0.1:9001"]}
    ]})
    .to_string();
    let fits = render_text_capped(&text, &budget(FIVE_KEYS + 1, usize::MAX))?;
    assert_eq!(refusals(&fits), Vec::new());
    let rendered = render_text_capped(&text, &budget(FIVE_KEYS - 1, usize::MAX))?;
    assert_eq!(refusals(&rendered), vec![(FIRST_ROUTE, TOO_MANY_RENDERED), (SECOND, TOO_MANY_RENDERED)]);
    Ok(())
}


#[test]
fn the_byte_budget_is_exact_for_the_written_document() -> Result<(), Box<dyn Error>> {
    let text = distinct_host_routes(THREE_ROUTES, &["/a", "/b"]);
    let everything = render_text_capped(&text, &budget(usize::MAX, usize::MAX))?;
    let total = document_bytes(&everything)?;
    let exact = render_text_capped(&text, &budget(usize::MAX, total))?;
    assert_eq!(refusals(&exact), Vec::new());
    let short = render_text_capped(&text, &budget(usize::MAX, total - 1))?;
    assert_eq!(refusals(&short), vec![(THIRD, TOO_MANY_BYTES)]);
    assert!(document_bytes(&short)? < total);
    Ok(())
}


#[test]
fn the_default_budget_bounds_a_full_file() -> Result<(), Box<dyn Error>> {
    let paths: Vec<String> = (0..MAX_PATHS).map(|i| format!("/p{i}")).collect();
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let rendered = render_text(&distinct_host_routes(MAX_ROUTES, &path_refs))?;
    assert_eq!(
        rendered.refused.len(),
        MAX_ROUTES - (MAX_RENDERED_UPSTREAMS - CATCH_ALL_UPSTREAMS) / MAX_PATHS
    );
    assert!(rendered.refused.iter().all(|refusal| refusal.reason == TOO_MANY_RENDERED));
    Ok(())
}


#[test]
fn sixteen_backends_on_sixteen_paths_keep_the_first_routes() -> Result<(), Box<dyn Error>> {
    let paths: Vec<String> = (0..MAX_PATHS).map(|i| format!("/p{i}")).collect();
    let backends: Vec<String> = (0..MAX_BACKENDS).map(|i| format!("127.0.0.{}:9001", i + 1)).collect();
    let routes: Vec<Value> = (0..MAX_ROUTES_WITH_16_BACKENDS)
        .map(|i| json!({"hosts": [format!("h{i}.test")], "paths": paths, "backends": backends}))
        .collect();
    let rendered = render_text(&json!({"routes": routes}).to_string())?;
    let kept = MAX_ROUTES_WITH_16_BACKENDS - rendered.refused.len();
    assert_eq!(kept, (MAX_RENDERED_UPSTREAMS - CATCH_ALL_UPSTREAMS) / (MAX_PATHS * MAX_BACKENDS));
    assert!(kept > 0);
    assert!(rendered.refused.iter().all(|refusal| refusal.reason == TOO_MANY_RENDERED));
    Ok(())
}


fn largest_host(route: usize, host: usize) -> String {
    format!(
        "{route:030}{host:030}.{}.{}.{}",
        "b".repeat(MAX_LABEL_BYTES),
        "c".repeat(MAX_LABEL_BYTES),
        "d".repeat(LAST_LABEL_BYTES)
    )
}


#[test]
fn the_largest_file_the_grammar_admits_never_meets_the_output_guard() -> Result<(), Box<dyn Error>> {
    let paths: Vec<String> = (0..MAX_PATHS)
        .map(|i| format!("/{}{i}", "p".repeat(MAX_PATH_BYTES - PATH_PADDING)))
        .collect();
    let backends: Vec<String> = (0..MAX_BACKENDS)
        .map(|i| format!("{}{i}:65535", "e".repeat(BACKEND_LABEL_BYTES)))
        .collect();
    let routes: Vec<Value> = (0..ROUTES_IN_LARGEST_FILE)
        .map(|i| {
            let hosts: Vec<String> = (0..MAX_HOSTS).map(|j| largest_host(i, j)).collect();
            json!({"hosts": hosts, "paths": paths, "backends": backends, "health": {"path": "/", "interval_seconds": MIN_INTERVAL_SECONDS}})
        })
        .collect();
    let text = json!({"routes": routes}).to_string();
    let mut written = Vec::new();
    let mut report = Vec::new();
    let count = render_to(&mut text.as_bytes(), &mut written, &mut report)?;
    assert!(written.len() <= MAX_JSON_BYTES);
    assert!(count > 0);
    assert!(count < routes.len());
    Ok(())
}
