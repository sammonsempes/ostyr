use serde_json::{json, Map, Value};
use std::error::Error;
use waf::limits::{
    DEFAULT_INTERVAL_SECONDS, MAX_BACKENDS, MAX_HOSTS, MAX_HOST_BYTES, MAX_INTERVAL_SECONDS, MAX_LABEL_BYTES, MAX_PATHS, MAX_PATH_BYTES,
    MIN_INTERVAL_SECONDS,
};
use waf::model::RawHealth;
use waf::validate::{
    check_backend, check_counts, check_health, check_host, check_path, convert_route, is_local, path_patterns, prefix_key, BAD_BACKEND, BAD_HEALTH,
    BAD_HOST, BAD_PATH, MALFORMED, NO_BACKEND, NO_HOST, TOO_MANY_BACKENDS, TOO_MANY_HOSTS, TOO_MANY_PATHS,
};


const EXTRA: usize = 1;


const SCALAR: u8 = 5;


const PORT_TOO_LONG: &str = "10.0.0.1:123456";


fn route_with(key: &str, value: Value) -> Value {
    let mut fields = Map::new();
    fields.insert("hosts".to_string(), json!(["a.test"]));
    fields.insert("backends".to_string(), json!(["127.0.0.1:9001"]));
    fields.insert(key.to_string(), value);
    Value::Object(fields)
}


#[test]
fn host_is_lowercased() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_host("Web.Example.TEST")?, "web.example.test");
    Ok(())
}


#[test]
fn bad_hosts_are_refused() -> Result<(), Box<dyn Error>> {
    let long_label = "a".repeat(MAX_LABEL_BYTES + EXTRA);
    let long_name = format!("{}.test", ["a"; MAX_HOST_BYTES].concat());
    let cases = [
        "",
        "-x.test",
        "x-.test",
        "a..test",
        "a.test.",
        "a b.test",
        "a\"b.test",
        "a}.test",
        "a{x}.test",
        "a\nb.test",
        "a\u{0}b.test",
        "a$.test",
        "\u{3164}.test",
        &long_label,
        &long_name,
    ];
    cases.iter().for_each(|case| assert_eq!(check_host(case), Err(BAD_HOST), "{case:?}"));
    Ok(())
}


#[test]
fn paths_are_checked() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_path("/api/v1.2/a-b_c~d")?, "/api/v1.2/a-b_c~d");
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    let cases = [
        "", "api", "/a/../b", "/a\"b", "/a}b", "/a\nb", "/a\u{0}b", "/a*", "/a?b", "/a%2e", "/{x}", " /a", &long, "/v1.", "/a./b", "/.", "/a//b",
        "//a",
    ];
    cases.iter().for_each(|case| assert_eq!(check_path(case), Err(BAD_PATH), "{case:?}"));
    Ok(())
}


#[test]
fn backends_are_checked() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_backend("Api.Internal:8080")?, "api.internal:8080");
    let cases = [
        "nocolon",
        "a.test:",
        "a.test:0",
        "a.test:65536",
        "a.test:80a",
        "a.test:+80",
        "a.test:000080",
        PORT_TOO_LONG,
        ":80",
        "-a.test:80",
        "a\"b:80",
        "a}:80",
        "a:8\n",
    ];
    cases
        .iter()
        .for_each(|case| assert_eq!(check_backend(case), Err(BAD_BACKEND), "{case:?}"));
    Ok(())
}


#[test]
fn prefixes_become_two_patterns() -> Result<(), Box<dyn Error>> {
    assert_eq!(path_patterns("/api/"), ["/api", "/api/*"]);
    assert_eq!(path_patterns("/api"), ["/api", "/api/*"]);
    assert_eq!(path_patterns("/"), ["/*"]);
    Ok(())
}


#[test]
fn health_defaults_and_bounds() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_health(None)?, ("/".to_string(), DEFAULT_INTERVAL_SECONDS));
    assert_eq!(
        check_health(Some(RawHealth {
            path: None,
            interval_seconds: None
        }))?,
        ("/".to_string(), DEFAULT_INTERVAL_SECONDS)
    );
    let good = RawHealth {
        path: Some("/up".to_string()),
        interval_seconds: Some(MAX_INTERVAL_SECONDS),
    };
    assert_eq!(check_health(Some(good))?, ("/up".to_string(), MAX_INTERVAL_SECONDS));
    let floor = RawHealth {
        path: None,
        interval_seconds: Some(MIN_INTERVAL_SECONDS),
    };
    assert_eq!(check_health(Some(floor))?, ("/".to_string(), MIN_INTERVAL_SECONDS));
    let below = RawHealth {
        path: None,
        interval_seconds: Some(MIN_INTERVAL_SECONDS - 1),
    };
    assert_eq!(check_health(Some(below)), Err(BAD_HEALTH));
    let zero = RawHealth {
        path: None,
        interval_seconds: Some(0),
    };
    assert_eq!(check_health(Some(zero)), Err(BAD_HEALTH));
    let high = RawHealth {
        path: None,
        interval_seconds: Some(MAX_INTERVAL_SECONDS + 1),
    };
    assert_eq!(check_health(Some(high)), Err(BAD_HEALTH));
    let bad_path = RawHealth {
        path: Some("up".to_string()),
        interval_seconds: None,
    };
    assert_eq!(check_health(Some(bad_path)), Err(BAD_HEALTH));
    Ok(())
}


#[test]
fn list_counts_are_bounded() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("hosts", MAX_HOSTS, TOO_MANY_HOSTS),
        ("paths", MAX_PATHS, TOO_MANY_PATHS),
        ("backends", MAX_BACKENDS, TOO_MANY_BACKENDS),
    ];
    cases.iter().for_each(|(key, max, reason)| {
        let exact = route_with(key, json!(vec!["x"; *max]));
        let over = route_with(key, json!(vec!["x"; *max + EXTRA]));
        assert_eq!(check_counts(&exact), Ok(()));
        assert_eq!(check_counts(&over), Err(*reason));
    });
    assert_eq!(check_counts(&json!(SCALAR)), Ok(()));
    Ok(())
}


#[test]
fn a_good_route_converts() -> Result<(), Box<dyn Error>> {
    let route = convert_route(route_with("paths", json!(["/x"])))?;
    assert_eq!(route.hosts, ["a.test"]);
    assert_eq!(route.prefixes, ["/x"]);
    assert_eq!(route.backends, ["127.0.0.1:9001"]);
    Ok(())
}


#[test]
fn every_refusal_has_its_reason() -> Result<(), Box<dyn Error>> {
    let cases = [
        (json!({"backends": ["a:1"]}), MALFORMED),
        (json!({"hosts": ["a.test"], "backends": ["a:1"], "extra": 1}), MALFORMED),
        (json!({"hosts": "a.test", "backends": ["a:1"]}), MALFORMED),
        (json!({"hosts": [], "backends": ["a:1"]}), NO_HOST),
        (json!({"hosts": ["a.test"], "backends": []}), NO_BACKEND),
        (route_with("hosts", json!(["a\"b.test"])), BAD_HOST),
        (route_with("hosts", json!(["a}.test"])), BAD_HOST),
        (route_with("hosts", json!(["a\nb.test"])), BAD_HOST),
        (route_with("hosts", json!(["a{b}.test"])), BAD_HOST),
        (route_with("hosts", json!(["-a.test"])), BAD_HOST),
        (route_with("paths", json!(["/a\"b"])), BAD_PATH),
        (route_with("paths", json!(["/a\u{0}b"])), BAD_PATH),
        (route_with("backends", json!(["a.test:0"])), BAD_BACKEND),
        (route_with("health", json!({"path": "up"})), BAD_HEALTH),
        (route_with("health", json!({"interval_seconds": 0})), BAD_HEALTH),
        (route_with("health", json!({"interval_seconds": 1})), BAD_HEALTH),
        (route_with("health", json!({"unknown": 1})), MALFORMED),
        (route_with("hosts", json!(vec!["a.test"; MAX_HOSTS + EXTRA])), TOO_MANY_HOSTS),
        (route_with("paths", json!(vec!["/a"; MAX_PATHS + EXTRA])), TOO_MANY_PATHS),
        (route_with("backends", json!(vec!["a:1"; MAX_BACKENDS + EXTRA])), TOO_MANY_BACKENDS),
    ];
    cases.into_iter().for_each(|(route, reason)| {
        let shown = route.to_string();
        assert_eq!(convert_route(route).err(), Some(reason), "{shown}");
    });
    Ok(())
}


#[test]
fn paths_are_lowercased() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_path("/API/V1")?, "/api/v1");
    assert_eq!(prefix_key("/api//"), "/api");
    assert_eq!(prefix_key("/"), "");
    Ok(())
}


#[test]
fn a_health_path_keeps_its_case() -> Result<(), Box<dyn Error>> {
    let mixed = RawHealth {
        path: Some("/Health".to_string()),
        interval_seconds: None,
    };
    assert_eq!(check_health(Some(mixed))?.0, "/Health");
    Ok(())
}


#[test]
fn a_health_path_cannot_be_an_authority() -> Result<(), Box<dyn Error>> {
    let authority = RawHealth {
        path: Some("//evil.test/hc".to_string()),
        interval_seconds: None,
    };
    assert_eq!(check_health(Some(authority)), Err(BAD_HEALTH));
    let dotted = RawHealth {
        path: Some("/v1.".to_string()),
        interval_seconds: None,
    };
    assert_eq!(check_health(Some(dotted)), Err(BAD_HEALTH));
    Ok(())
}


#[test]
fn the_admin_api_is_never_a_backend() -> Result<(), Box<dyn Error>> {
    let refused = [
        "127.0.0.1:2019",
        "127.1.2.3:2019",
        "0.0.0.0:2019",
        "localhost:2019",
        "LOCALHOST:2019",
        "a.localhost:2019",
        "2130706433:2019",
        "0x7f.0.0.1:2019",
    ];
    refused
        .iter()
        .for_each(|case| assert_eq!(check_backend(case), Err(BAD_BACKEND), "{case}"));
    let accepted = ["10.0.0.1:2019", "a.test:2019", "127.0.0.1:2020", "localhost:9001"];
    accepted.iter().for_each(|case| assert!(check_backend(case).is_ok(), "{case}"));
    assert!(is_local("127.0.0.1"));
    assert!(!is_local("10.0.0.1"));
    Ok(())
}
