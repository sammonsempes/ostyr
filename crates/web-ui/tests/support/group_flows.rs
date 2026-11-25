use super::{assert_hardened, assert_no_hidden_characters, set_mode};
use crate::harness::{fire, get, get_with, harness, location_of, sign_in, without_tokens, Harness, Req};
use crate::stub::{group_json, group_list_json, id_of, Mode};
use crate::types::{TestError, TestResult};
use axum::http::StatusCode;
use serde_json::{json, Value};
use web_ui::api::{scan_groups, GROUPS_BODY_LIMIT, GROUPS_ENTITY_CHARS, GROUPS_RULE_CHARS, MAX_BODY_BYTES, MAX_GROUPS, MAX_GROUP_IDS};


const HOSTILE_RULE: &str = "<script>x</script>&\"\u{1b}\u{202e}";


const HOSTILE_RULE_ESCAPED: &str = "<td>&lt;script&gt;x&lt;/script&gt;&amp;&quot;\u{fffd}\u{fffd}</td>";


const GROUP_ROWS: usize = 2;


const BIG_HOST_CHARS: usize = 65_536;


const OVER_CAP_RULE_CHARS: usize = 8_388_608;


const ESC: char = '\u{1b}';


fn set(target: &mut Value, key: &str, value: Value) -> TestResult {
    target.as_object_mut().ok_or("not an object")?.insert(key.to_owned(), value);
    Ok(())
}


fn set_groups(rig: &Harness, reply: Option<Value>) -> TestResult {
    *rig.stub.state.groups_reply.lock().map_err(|_| "poisoned")? = reply;
    Ok(())
}


fn group_requests(rig: &Harness) -> Result<Vec<String>, TestError> {
    Ok(rig.stub.state.group_paths.lock().map_err(|_| "poisoned")?.clone())
}


#[tokio::test]
async fn the_groups_page_lists_one_row_per_group_and_the_alerts_page_links_to_it() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let alerts = fire(&rig, get_with("/alerts", &session)).await?;
    assert!(alerts.body.contains("action=\"/alert-groups\""));
    let page = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert_hardened(&page);
    assert_eq!(page.body.matches("<tr><td>rule-").count(), GROUP_ROWS);
    for expected in [
        "Alert groups",
        "<td>rule-a</td>",
        "<td>rule-b</td>",
        "<td>web01</td>",
        "<td>3</td>",
        "<td>1</td>",
        "<td>high</td>",
        "2026-03-01T00:05:00Z",
        "42 alerts read, oldest read: 2026-02-28T00:00:00Z",
        &format!("action=\"/alerts/{}\"", id_of('a')),
        &format!("action=\"/alerts/{}\"", id_of('b')),
    ] {
        assert!(page.body.contains(expected), "{expected}: {}", page.body);
    }
    assert!(!page.body.contains("were not read"));
    let french = fire(
        &rig,
        Req {
            language: Some("fr".to_owned()),
            ..get_with("/alert-groups", &session)
        },
    )
    .await?;
    assert!(french.body.contains("Groupes d'alertes") && french.body.contains("42 alertes lues"));
    assert_eq!(group_requests(&rig)?, ["/alert-groups", "/alert-groups"]);
    Ok(())
}


#[tokio::test]
async fn an_incomplete_read_shows_the_notice_before_the_table_and_the_notes() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let mut cut = group_json("rule-c", &id_of('c'));
    set(&mut cut, "cut_at_older", json!(true))?;
    let mut omitted = group_json("rule-d", &id_of('d'));
    set(&mut omitted, "omitted", json!(true))?;
    let mut reply = group_list_json(vec![cut, omitted], false);
    set(&mut reply, "oldest_read", Value::Null)?;
    set_groups(&rig, Some(reply))?;
    let page = fire(&rig, get_with("/alert-groups", &session)).await?;
    let notice = page
        .body
        .find("Older alerts were not read; counts may be understated.")
        .ok_or("no notice")?;
    let table = page.body.find("<table>").ok_or("no table")?;
    assert!(notice < table);
    assert!(page.body.contains("may be understated</td>") && page.body.contains("ids omitted </td>"));
    assert!(page.body.contains("oldest read: (none)"));
    set_groups(&rig, Some(group_list_json(vec![], true)))?;
    let empty = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert!(empty.body.contains("No group.") && !empty.body.contains("<table>") && !empty.body.contains("were not read"));
    Ok(())
}


#[tokio::test]
async fn hostile_group_values_are_escaped_and_a_bad_representative_is_never_a_link() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let mut hostile = group_json(HOSTILE_RULE, "javascript:alert(1)");
    set(&mut hostile, "host_name", json!("x\"><img src=x onerror=alert(2)>"))?;
    set(&mut hostile, "user_name", json!("a".repeat(BIG_HOST_CHARS)))?;
    set(&mut hostile, "max_severity", json!("<b>"))?;
    set(&mut hostile, "first_time", json!("\u{1b}[31m"))?;
    let relative = group_json("rule-e", "../x");
    set_groups(&rig, Some(group_list_json(vec![hostile, relative], true)))?;
    let page = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert_eq!(page.status, StatusCode::OK);
    assert_hardened(&page);
    assert_no_hidden_characters(&page.body);
    let body = without_tokens(&page.body);
    assert!(body.contains(HOSTILE_RULE_ESCAPED), "{body}");
    assert!(body.contains("<td>&lt;b&gt;</td>") && body.contains("<td>\u{fffd}[31m</td>"));
    assert!(body.contains("omitted]") && body.len() < BIG_HOST_CHARS);
    assert!(!body.contains("<script") && !body.contains("<img") && !body.contains("<b>"));
    assert!(body.contains("<td>javascript:alert(1)</td>") && body.contains("<td>../x</td>"));
    assert!(!body.contains("action=\"/alerts/javascript") && !body.contains("action=\"/alerts/../x"));
    Ok(())
}


#[tokio::test]
async fn a_query_is_refused_a_session_is_needed_and_api_failures_get_our_pages() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    for path in ["/alert-groups?limit=5", "/alert-groups?tenant=b", "/alert-groups?x="] {
        let reply = fire(&rig, get_with(path, &session)).await?;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(group_requests(&rig)?.is_empty());
    let anonymous = fire(&rig, get("/alert-groups")).await?;
    assert_eq!(location_of(&anonymous).as_deref(), Some("/login"));
    assert!(group_requests(&rig)?.is_empty());
    for (status, shown) in [
        (StatusCode::TOO_MANY_REQUESTS, StatusCode::TOO_MANY_REQUESTS),
        (StatusCode::SERVICE_UNAVAILABLE, StatusCode::BAD_GATEWAY),
        (StatusCode::FORBIDDEN, StatusCode::FORBIDDEN),
    ] {
        set_mode(&rig, Mode::Status(status))?;
        let reply = fire(&rig, get_with("/alert-groups", &session)).await?;
        assert_eq!(reply.status, shown);
        assert_hardened(&reply);
    }
    set_mode(&rig, Mode::Status(StatusCode::UNAUTHORIZED))?;
    let ended = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert_eq!(location_of(&ended).as_deref(), Some("/login"));
    Ok(())
}


#[tokio::test]
async fn an_out_of_bound_or_malformed_reply_is_a_bad_gateway_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let many: Vec<Value> = (0..=MAX_GROUPS).map(|_| group_json("r", &id_of('a'))).collect();
    let mut crowded = group_json("r", &id_of('a'));
    set(&mut crowded, "alert_ids", json!(vec![id_of('a'); MAX_GROUP_IDS + 1]))?;
    let mut wrong_type = group_json("r", &id_of('a'));
    set(&mut wrong_type, "alert_count", json!("many"))?;
    for reply in [
        group_list_json(many, true),
        group_list_json(vec![crowded], true),
        group_list_json(vec![wrong_type], true),
        json!({"groups": 1}),
    ] {
        set_groups(&rig, Some(reply))?;
        let page = fire(&rig, get_with("/alert-groups", &session)).await?;
        assert_eq!(page.status, StatusCode::BAD_GATEWAY);
        assert_hardened(&page);
    }
    Ok(())
}


#[test]
fn the_pre_scan_accepts_the_bounds_exactly() -> TestResult {
    let full: Vec<Value> = (0..MAX_GROUPS).map(|_| group_json("r", &id_of('a'))).collect();
    scan_groups(group_list_json(full, true).to_string().as_bytes())?;
    let mut widest = group_json("r", &id_of('a'));
    set(&mut widest, "alert_ids", json!(vec![id_of('a'); MAX_GROUP_IDS]))?;
    scan_groups(group_list_json(vec![widest], true).to_string().as_bytes())?;
    assert!(scan_groups(b"not json").is_err());
    Ok(())
}


fn worst_case_group() -> Result<Value, TestError> {
    let mut group = group_json(&ESC.to_string().repeat(GROUPS_RULE_CHARS), &id_of('a'));
    set(&mut group, "host_name", json!(ESC.to_string().repeat(GROUPS_ENTITY_CHARS)))?;
    set(&mut group, "user_name", json!(ESC.to_string().repeat(GROUPS_ENTITY_CHARS)))?;
    set(&mut group, "alert_ids", json!(vec![id_of('a'); MAX_GROUP_IDS]))?;
    Ok(group)
}


#[test]
fn the_worst_case_reply_fits_the_groups_cap_and_the_old_cap_does_not() -> TestResult {
    let group = worst_case_group()?;
    let reply = group_list_json((0..MAX_GROUPS).map(|_| group.clone()).collect(), false).to_string();
    assert!(reply.len() <= GROUPS_BODY_LIMIT, "{} > {GROUPS_BODY_LIMIT}", reply.len());
    assert!(reply.len() > MAX_BODY_BYTES);
    scan_groups(reply.as_bytes())?;
    Ok(())
}


#[tokio::test]
async fn a_worst_case_reply_renders_and_a_reply_over_the_cap_is_the_named_page() -> TestResult {
    let rig = harness(Mode::Normal).await?;
    let session = sign_in(&rig).await?;
    let group = worst_case_group()?;
    set_groups(&rig, Some(group_list_json((0..MAX_GROUPS).map(|_| group.clone()).collect(), true)))?;
    let shown = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert_eq!(shown.status, StatusCode::OK);
    assert_hardened(&shown);
    let huge = group_json(&"x".repeat(OVER_CAP_RULE_CHARS), &id_of('a'));
    set_groups(&rig, Some(group_list_json(vec![huge], true)))?;
    let page = fire(&rig, get_with("/alert-groups", &session)).await?;
    assert_eq!(page.status, StatusCode::BAD_GATEWAY);
    assert_hardened(&page);
    assert!(page.body.contains("The alert groups are too large to show."));
    assert!(!page.body.contains("The service is not available"));
    Ok(())
}
