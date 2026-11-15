use serde_json::{json, Value};
use std::error::Error;
use waf::cli::refusal_line;
use waf::model::Refusal;
use waf::render::render_text;
use waf::validate::SHADOWED;


const THIRD_BACKEND: usize = 2;


const WITH_CATCH_ALL: usize = 2;


const TWO_ROUTES_AND_CATCH_ALL: usize = 3;


const FOURTH_ROUTE: usize = 4;


const OWNER_ROUTE: usize = 2;


const NOT_FOUND: u16 = 404;


const BACKENDS: [&str; 3] = [FIRST, SECOND, THIRD];


const FIRST: &str = "127.0.0.1:9001";


const SECOND: &str = "127.0.0.1:9002";


const THIRD: &str = "127.0.0.1:9003";


fn route(hosts: &[&str], paths: &[&str], backend: usize) -> Value {
    json!({"hosts": hosts, "paths": paths, "backends": [BACKENDS.get(backend)]})
}


fn rendered_routes(routes: &[Value]) -> Result<(Vec<Value>, Vec<Refusal>), Box<dyn Error>> {
    let rendered = render_text(&json!({ "routes": routes }).to_string())?;
    let document = serde_json::to_value(&rendered.config)?;
    let listed = document
        .pointer("/apps/http/servers/main/routes")
        .and_then(Value::as_array)
        .cloned()
        .ok_or("no routes")?;
    Ok((listed, rendered.refused))
}


fn dials(listed: &[Value]) -> Vec<String> {
    listed
        .iter()
        .map(|entry| {
            entry
                .pointer("/handle/0/upstreams/0/dial")
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string()
        })
        .collect()
}


#[test]
fn a_path_route_comes_before_a_host_only_route() -> Result<(), Box<dyn Error>> {
    let (listed, refused) = rendered_routes(&[route(&["a.test"], &[], 0), route(&["a.test"], &["/admin"], 1)])?;
    assert!(refused.is_empty());
    assert_eq!(dials(&listed), [SECOND, FIRST, "none"]);
    Ok(())
}


#[test]
fn longer_prefixes_come_first_and_ties_keep_file_order() -> Result<(), Box<dyn Error>> {
    let routes = [
        route(&["a.test"], &["/a"], 0),
        route(&["a.test"], &["/a/b/c", "/zz"], 1),
        route(&["a.test"], &["/b"], THIRD_BACKEND),
    ];
    let (listed, refused) = rendered_routes(&routes)?;
    assert!(refused.is_empty());
    assert_eq!(dials(&listed), [SECOND, SECOND, FIRST, THIRD, "none"]);
    Ok(())
}


#[test]
fn a_second_host_only_route_on_a_host_is_shadowed() -> Result<(), Box<dyn Error>> {
    let (listed, refused) = rendered_routes(&[route(&["a.test"], &[], 0), route(&["a.test"], &[], 1)])?;
    assert_eq!(listed.len(), WITH_CATCH_ALL);
    assert_eq!(
        refused,
        [Refusal {
            index: 1,
            reason: SHADOWED,
            shadowed_by: Some(0)
        }]
    );
    Ok(())
}


#[test]
fn prefixes_equal_after_lowercasing_and_trimming_are_shadowed() -> Result<(), Box<dyn Error>> {
    let (_, refused) = rendered_routes(&[route(&["a.test"], &["/api"], 0), route(&["a.test"], &["/API/"], 1)])?;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused.first().map(|refusal| refusal.shadowed_by), Some(Some(0)));
    Ok(())
}


#[test]
fn a_route_with_one_new_pair_is_kept() -> Result<(), Box<dyn Error>> {
    let routes = [route(&["a.test"], &["/x"], 0), route(&["a.test", "b.test"], &["/x"], 1)];
    let (listed, refused) = rendered_routes(&routes)?;
    assert!(refused.is_empty());
    assert_eq!(listed.len(), TWO_ROUTES_AND_CATCH_ALL);
    Ok(())
}


#[test]
fn the_root_path_and_a_host_only_route_collide() -> Result<(), Box<dyn Error>> {
    let (_, refused) = rendered_routes(&[route(&["a.test"], &["/"], 0), route(&["a.test"], &[], 1)])?;
    assert_eq!(refused.len(), 1);
    Ok(())
}


#[test]
fn a_shadowed_route_is_reported_with_its_owner() -> Result<(), Box<dyn Error>> {
    let shadowed = Refusal {
        index: FOURTH_ROUTE,
        reason: SHADOWED,
        shadowed_by: Some(OWNER_ROUTE),
    };
    assert_eq!(refusal_line(&shadowed), "route 4 refused: shadowed by route 2");
    Ok(())
}


#[test]
fn the_last_route_answers_404() -> Result<(), Box<dyn Error>> {
    let (listed, _) = rendered_routes(&[])?;
    assert_eq!(listed, [json!({"handle": [{"handler": "static_response", "status_code": NOT_FOUND}]})]);
    Ok(())
}
