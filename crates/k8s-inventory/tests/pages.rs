#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/types.rs"]
mod types;


use fixtures::{list, node, pod, set, uid};
use k8s_inventory::diff::diff;
use k8s_inventory::error::ParseError;
use k8s_inventory::inventory::build_inventory;
use k8s_inventory::limits::{Limits, PageLimits, CEILING_PAGES, CEILING_TOTAL_ITEMS, DEFAULT_MAX_PAGES, DEFAULT_MAX_TOTAL_ITEMS, MAX_CONTINUE_BYTES};
use k8s_inventory::model::{NodeItem, Page, Parsed, PodItem};
use k8s_inventory::pages::{merge_node_pages, merge_pages, merge_pod_pages, page_size, remaining_budget};
use k8s_inventory::parse::{parse_nodes, parse_nodes_page, parse_pods, parse_pods_page, pod_uid};
use k8s_inventory::text::valid_continue;
use serde_json::{json, Value};
use types::TestResult;


const PODS_BEFORE: &[u8] = include_bytes!("fixtures/pods-before.json");


const NODES: &[u8] = include_bytes!("fixtures/nodes.json");


const K3S_TOKEN: &str = "eyJ2IjoibWV0YS5rOHMuaW8vdjEiLCJydiI6ODAwLCJzdGFydCI6Ii9kZWZhdWx0L3dlYi03OTlmNjg5Y2Q4LWNkYmR0XHUwMDAwIn0";


const THREE: usize = 3;


const FOUR: usize = 4;


const DEFAULT_PAGE: usize = 512;


const TWO: usize = 2;


const SMALL_PAGES: usize = 3;


const SMALL_TOTAL: usize = 3;


const OVER_THE_CAP: usize = 1;


fn page_text(kind: &str, items: Vec<Value>, next: Option<&str>) -> Vec<u8> {
    json!({"kind": kind, "metadata": {"continue": next.unwrap_or("")}, "items": items})
        .to_string()
        .into_bytes()
}


fn pod_page(items: Vec<Value>, next: Option<&str>) -> Result<Page<PodItem>, ParseError> {
    parse_pods_page(page_text("PodList", items, next).as_slice(), &Limits::default(), DEFAULT_MAX_TOTAL_ITEMS)
}


fn small() -> PageLimits {
    PageLimits {
        max_pages: SMALL_PAGES,
        max_total_items: SMALL_TOTAL,
    }
}


fn merged(pages: Vec<Page<PodItem>>) -> Result<Parsed<PodItem>, ParseError> {
    merge_pod_pages(pages, &PageLimits::default())
}


#[test]
fn three_pages_of_the_live_fixture_merge_to_the_one_document_read() -> TestResult {
    let whole = parse_pods(PODS_BEFORE, &Limits::default())?;
    let document: Value = serde_json::from_slice(PODS_BEFORE)?;
    let items = document.get("items").and_then(Value::as_array).ok_or("no items")?;
    let per_page = items.len().div_ceil(THREE);
    let chunks = items.chunks(per_page).map(<[Value]>::to_vec).collect::<Vec<_>>();
    assert_eq!(chunks.len(), THREE);
    let tokens = [Some("first-token"), Some("second_token=.x"), None];
    let pages = chunks
        .into_iter()
        .zip(tokens)
        .map(|(chunk, token)| pod_page(chunk, token))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(pages.first().and_then(|page| page.next.as_deref()), Some("first-token"));
    assert_eq!(merged(pages)?, whole);
    Ok(())
}


#[test]
fn a_uid_kept_on_page_one_and_repeated_on_page_three_counts_one_duplicate() -> TestResult {
    let first = pod_page(vec![pod("first-name", "u-a")], Some("t1"))?;
    let middle = pod_page(vec![pod("other", "u-b")], Some("t2"))?;
    let last = pod_page(vec![pod("second-name", "u-a")], None)?;
    let result = merged(vec![first, middle, last])?;
    assert_eq!(result.skipped.duplicate, 1);
    assert_eq!(
        result.items.iter().map(|item| item.name.as_str()).collect::<Vec<_>>(),
        vec!["first-name", "other"]
    );
    Ok(())
}


#[test]
fn a_uid_refused_on_page_one_and_kept_on_page_two_leaves_the_refused_set_like_one_page() -> TestResult {
    let mut refused = pod("Web", "u-a");
    set(&mut refused, "/metadata/name", json!("Web"))?;
    let kept = pod("web", "u-a");
    let across = merged(vec![pod_page(vec![refused.clone()], Some("t1"))?, pod_page(vec![kept.clone()], None)?])?;
    let within = parse_pods(page_text("PodList", vec![refused, kept], None).as_slice(), &Limits::default())?;
    assert_eq!(across.skipped.refused_uids, Vec::<String>::new());
    assert_eq!((across.skipped.bad_field, across.skipped.duplicate), (1, 1));
    assert_eq!(across, within);
    Ok(())
}


#[test]
fn a_refused_uid_seen_on_two_pages_is_listed_once() -> TestResult {
    let refused = json!({"metadata": {"name": "Web", "namespace": "default", "uid": uid("u-r")}});
    let result = merged(vec![pod_page(vec![refused.clone()], Some("t1"))?, pod_page(vec![refused], None)?])?;
    assert_eq!(result.skipped.refused_uids, vec![uid("u-r")]);
    assert_eq!(result.skipped.bad_field, TWO);
    Ok(())
}


#[test]
fn a_last_page_that_announces_a_token_is_incomplete() -> TestResult {
    let result = merged(vec![pod_page(vec![pod("a", "u-a")], Some("t1"))?]);
    assert!(matches!(result, Err(ParseError::Incomplete)));
    Ok(())
}


#[test]
fn a_page_without_a_token_in_the_middle_or_no_page_at_all_is_incomplete() -> TestResult {
    let middle = merged(vec![pod_page(vec![], None)?, pod_page(vec![], None)?]);
    assert!(matches!(middle, Err(ParseError::Incomplete)));
    assert!(matches!(merged(Vec::new()), Err(ParseError::Incomplete)));
    Ok(())
}


#[test]
fn a_server_that_never_stops_is_cut_at_max_pages_and_nothing_is_built() -> TestResult {
    let limits = small();
    let endless = (0..=limits.max_pages)
        .map(|_| pod_page(vec![], Some("again")))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(merge_pod_pages(endless, &limits), Err(ParseError::Incomplete)));
    let ends = (0..=limits.max_pages)
        .map(|index| pod_page(vec![], if index == limits.max_pages { None } else { Some("more") }))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(merge_pod_pages(ends, &limits), Err(ParseError::Incomplete)));
    let exact = (0..limits.max_pages)
        .map(|index| pod_page(vec![], if index + 1 == limits.max_pages { None } else { Some("more") }))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(merge_pod_pages(exact, &limits)?.items.is_empty());
    Ok(())
}


#[test]
fn one_item_over_max_total_items_is_refused_and_exactly_max_is_accepted() -> TestResult {
    let limits = small();
    let items = |tags: &[&str]| tags.iter().map(|tag| pod(tag, tag)).collect::<Vec<_>>();
    let over = vec![pod_page(items(&["a", "b"]), Some("t"))?, pod_page(items(&["c", "d"]), None)?];
    assert!(matches!(
        merge_pod_pages(over, &limits),
        Err(ParseError::TooManyItems {
            count: FOUR,
            max: SMALL_TOTAL
        })
    ));
    let exact = vec![pod_page(items(&["a", "b"]), Some("t"))?, pod_page(items(&["c"]), None)?];
    assert_eq!(remaining_budget(&exact, &limits), 0);
    assert_eq!(merge_pod_pages(exact, &limits)?.items.len(), THREE);
    Ok(())
}


#[test]
fn a_page_that_crosses_the_budget_is_refused_before_any_element_is_converted() -> TestResult {
    let limits = Limits::default();
    let items = vec![pod("a", "a"), pod("b", "b"), json!(0)];
    let refused = parse_pods_page(page_text("PodList", items.clone(), None).as_slice(), &limits, TWO);
    assert!(matches!(refused, Err(ParseError::TooManyItems { count: THREE, max: TWO })));
    let accepted = parse_pods_page(page_text("PodList", items, None).as_slice(), &limits, THREE)?;
    assert_eq!(
        (accepted.raw_count, accepted.parsed.items.len(), accepted.parsed.skipped.unparsable),
        (THREE, TWO, 1)
    );
    Ok(())
}


#[test]
fn skipped_counters_are_summed_over_the_pages() -> TestResult {
    let bad = json!({"metadata": {"name": "p"}});
    let result = merged(vec![pod_page(vec![bad.clone(), json!(0)], Some("t"))?, pod_page(vec![bad], None)?])?;
    assert_eq!(
        (result.skipped.bad_field, result.skipped.unparsable, result.skipped.uid_lost),
        (TWO, 1, THREE)
    );
    Ok(())
}


#[test]
fn every_bad_continue_is_refused_without_echoing_a_byte() -> TestResult {
    let long = "a".repeat(MAX_CONTINUE_BYTES + OVER_THE_CAP);
    let bad = ["abc def", "a\u{3164}", long.as_str(), "%2F", "a/b", "a&limit=100000", "a\nb", "a+b", "é"];
    bad.iter().try_for_each(|token| -> TestResult {
        let outcome = parse_pods_page(page_text("PodList", vec![], Some(token)).as_slice(), &Limits::default(), 1);
        let error = outcome.err().ok_or("accepted")?;
        assert!(matches!(error, ParseError::BadContinue), "{token:?}");
        assert_eq!(error.to_string(), "the continue token is outside the allowed grammar");
        assert_eq!(format!("{error:?}"), "BadContinue");
        Ok(())
    })?;
    Ok(())
}


#[test]
fn an_empty_or_absent_continue_is_the_last_page_and_a_real_k3s_token_is_kept() -> TestResult {
    let empty = pod_page(vec![], None)?;
    assert_eq!(empty.next, None);
    let absent = parse_pods_page(br#"{"kind":"PodList","items":[]}"#.as_slice(), &Limits::default(), 1)?;
    assert_eq!(absent.next, None);
    let nulled = parse_pods_page(br#"{"kind":"PodList","metadata":null,"items":[]}"#.as_slice(), &Limits::default(), 1)?;
    assert_eq!(nulled.next, None);
    let real = pod_page(vec![], Some(K3S_TOKEN))?;
    assert_eq!(real.next.as_deref(), Some(K3S_TOKEN));
    assert!(!valid_continue(""));
    let longest = "a".repeat(MAX_CONTINUE_BYTES);
    assert_eq!(pod_page(vec![], Some(&longest))?.next, Some(longest));
    Ok(())
}


#[test]
fn a_whole_read_that_announces_a_token_is_incomplete() -> TestResult {
    let partial = parse_pods(page_text("PodList", vec![pod("a", "a")], Some("t")).as_slice(), &Limits::default());
    assert!(matches!(partial, Err(ParseError::Incomplete)));
    Ok(())
}


#[test]
fn page_limits_above_their_ceilings_are_refused() -> TestResult {
    let default = PageLimits::default();
    assert_eq!((default.max_pages, default.max_total_items), (DEFAULT_MAX_PAGES, DEFAULT_MAX_TOTAL_ITEMS));
    let pages_over = PageLimits {
        max_pages: CEILING_PAGES + 1,
        ..default.clone()
    };
    let total_over = PageLimits {
        max_total_items: CEILING_TOTAL_ITEMS + 1,
        ..default.clone()
    };
    let at_ceiling = PageLimits {
        max_pages: CEILING_PAGES,
        max_total_items: CEILING_TOTAL_ITEMS,
    };
    let last = || pod_page(vec![], None).map(|page| vec![page]);
    assert!(matches!(merge_pod_pages(last()?, &pages_over), Err(ParseError::BadPageLimits)));
    assert!(matches!(merge_pod_pages(last()?, &total_over), Err(ParseError::BadPageLimits)));
    assert!(merge_pod_pages(last()?, &at_ceiling).is_ok());
    Ok(())
}


#[test]
fn the_page_size_follows_the_byte_rule_and_the_item_cap() -> TestResult {
    let defaults = Limits::default();
    assert_eq!(page_size(&defaults), DEFAULT_PAGE);
    let few = Limits {
        max_items: TWO,
        ..defaults.clone()
    };
    assert_eq!(page_size(&few), TWO);
    let tiny = Limits { max_bytes: 1, ..defaults };
    assert_eq!(page_size(&tiny), 1);
    Ok(())
}


#[test]
fn node_pages_merge_like_pod_pages() -> TestResult {
    let nodes = |items: Vec<Value>, next: Option<&str>| -> Result<Page<NodeItem>, ParseError> {
        parse_nodes_page(page_text("NodeList", items, next).as_slice(), &Limits::default(), DEFAULT_MAX_TOTAL_ITEMS)
    };
    let result = merge_node_pages(
        vec![
            nodes(vec![node("n1", "n1")], Some("t"))?,
            nodes(vec![node("n1", "n1"), node("n2", "n2")], None)?,
        ],
        &PageLimits::default(),
    )?;
    assert_eq!((result.items.len(), result.skipped.duplicate), (TWO, 1));
    let listed = parse_nodes_page(list("NodeList", vec![node("n3", "n3")]).as_slice(), &Limits::default(), 1)?;
    assert_eq!((listed.next, listed.raw_count), (None, 1));
    let whole = parse_nodes(NODES, &Limits::default())?;
    let one = merge_node_pages(
        vec![parse_nodes_page(NODES, &Limits::default(), DEFAULT_MAX_TOTAL_ITEMS)?],
        &PageLimits::default(),
    )?;
    assert_eq!(one, whole);
    Ok(())
}


#[test]
fn a_page_that_repeats_every_uid_of_page_one_changes_nothing() -> TestResult {
    let first = vec![pod("a", "a"), pod("b", "b")];
    let renamed = vec![pod("x", "a"), pod("y", "b")];
    let result = merged(vec![pod_page(first.clone(), Some("t"))?, pod_page(renamed, None)?])?;
    assert_eq!(result.skipped.duplicate, TWO);
    let single = merged(vec![pod_page(first, None)?])?;
    assert_eq!(result.items, single.items);
    let previous = build_inventory("t", "c", single, empty_nodes())?;
    let current = build_inventory("t", "c", result, empty_nodes())?;
    let changes = diff(&previous, &current)?;
    assert!(changes.changed.is_empty() && changes.created.is_empty() && changes.retired.is_empty());
    Ok(())
}


fn empty_nodes() -> Parsed<NodeItem> {
    Parsed {
        items: Vec::new(),
        skipped: k8s_inventory::model::Skipped::default(),
    }
}


#[test]
fn a_uid_refused_on_page_one_and_absent_elsewhere_is_unreadable_never_retired() -> TestResult {
    let previous = build_inventory(
        "t",
        "c",
        merged(vec![pod_page(vec![pod("a", "a"), pod("b", "b")], None)?])?,
        empty_nodes(),
    )?;
    let refused = json!({"metadata": {"name": "Web", "namespace": "default", "uid": uid("a")}});
    let current_pods = merged(vec![pod_page(vec![refused], Some("t"))?, pod_page(vec![pod("b", "b")], None)?])?;
    let current = build_inventory("t", "c", current_pods, empty_nodes())?;
    let changes = diff(&previous, &current)?;
    assert!(changes.retired.is_empty());
    assert_eq!(changes.unreadable.iter().map(|item| item.uid.clone()).collect::<Vec<_>>(), vec![uid("a")]);
    Ok(())
}


#[test]
fn look_alike_pod_names_are_bad_fields_and_keep_their_uid() -> TestResult {
    let upper = json!({"metadata": {"name": "Web", "namespace": "default", "uid": uid("upper")}});
    let hidden = json!({"metadata": {"name": "web\u{3164}", "namespace": "default", "uid": uid("hidden")}});
    let parsed = parse_pods(page_text("PodList", vec![upper, hidden], None).as_slice(), &Limits::default())?;
    assert_eq!((parsed.items.len(), parsed.skipped.bad_field), (0, TWO));
    assert_eq!(parsed.skipped.refused_uids, vec![uid("upper"), uid("hidden")]);
    Ok(())
}


#[test]
fn merge_pages_is_generic_over_the_uid_function() -> TestResult {
    let page = pod_page(vec![pod("a", "a")], None)?;
    assert_eq!(merge_pages(vec![page], &PageLimits::default(), pod_uid)?.items.len(), 1);
    Ok(())
}
