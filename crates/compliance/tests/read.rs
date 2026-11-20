#[path = "common/state_fake.rs"]
mod state_fake;
#[path = "common/types.rs"]
mod types;


use compliance::alerting::{MAX_ASSET_CHARS, MAX_ID_CHARS};
use compliance::error::ReadError;
use compliance::read::{
    asset_state, decode_cursor, encode_cursor, is_asset, key_ok, limit_text, list_state, parse_row, statement_of, stored_of, ASSET_SQL,
    LIST_ALL_BASELINE_SQL, LIST_ALL_SQL, LIST_VERDICT_BASELINE_SQL, LIST_VERDICT_SQL, MAX_ASSET_RESULTS, MAX_CURSOR_HEX, MAX_PAGE,
};
use compliance::read_model::StateFilter;
use compliance::types::StateKey;
use core_pg::scope::tenant_scope;
use state_fake::{capture_dispatch, captured, executor, put, recorded, Capture, Fake, FOURTH};
use types::TestResult;


const TENANT: &str = "acme";


const OTHER: &str = "globex";


const SEEN: &str = "1700000000000000";


const FAILED: &str = "1600000000000000";


const SECOND: usize = 2;


const THIRD: usize = 3;


const FIFTH: usize = 5;


const SIXTH: usize = 6;


fn key(baseline: &str, control: &str, asset: &str) -> StateKey {
    (baseline.to_owned(), control.to_owned(), asset.to_owned())
}


fn filter(verdict: Option<&str>, baseline: Option<&str>) -> StateFilter {
    StateFilter {
        verdict: verdict.map(str::to_owned),
        baseline: baseline.map(str::to_owned),
    }
}


fn seed_three(fake: &Fake) {
    put(fake, TENANT, ("base", "c1", "host-a"), ("fail", FAILED, SEEN));
    put(fake, TENANT, ("base", "c1", "host-b"), ("fail", FAILED, SEEN));
    put(fake, TENANT, ("base", "c2", "host-a"), ("fail", FAILED, SEEN));
    put(fake, TENANT, ("base", "c3", "host-a"), ("pass", "", SEEN));
    put(fake, TENANT, ("other", "c1", "host-a"), ("error", "", SEEN));
    put(fake, OTHER, ("base", "c1", "host-z"), ("fail", FAILED, SEEN));
}


#[test]
fn the_cursor_round_trips_and_the_longest_key_fits_the_bound() -> TestResult {
    let sample = key("base", "c1", "host/a:b@c~1^2+3");
    assert_eq!(decode_cursor(&encode_cursor(&sample))?, sample);
    let longest = key(&"b".repeat(MAX_ID_CHARS), &"c".repeat(MAX_ID_CHARS), &"a".repeat(MAX_ASSET_CHARS));
    let text = encode_cursor(&longest);
    assert_eq!(text.len(), MAX_CURSOR_HEX);
    assert_eq!(decode_cursor(&text)?, longest);
    Ok(())
}


#[test]
fn a_forged_cursor_is_refused() -> TestResult {
    let good = encode_cursor(&key("base", "c1", "host-a"));
    let uppercase = good.to_ascii_uppercase();
    let two_fields = hex("base\0c1");
    let four_fields = hex("base\0c1\0host\0x");
    let no_separator = hex("basec1host");
    let invalid_utf8 = "ff00ff00ff".to_owned();
    let leading_dash = hex("base\0c1\0-host");
    let long_baseline = hex(&format!("{}\0c1\0host", "b".repeat(MAX_ID_CHARS + 1)));
    let empty_field = hex("base\0\0host");
    let space = hex("base\0c1\0ho st");
    let too_long = "a".repeat(MAX_CURSOR_HEX + SECOND);
    let bad = [
        String::new(),
        format!("{good}0"),
        "zz".to_owned(),
        uppercase,
        two_fields,
        four_fields,
        no_separator,
        invalid_utf8,
        leading_dash,
        long_baseline,
        empty_field,
        space,
        too_long,
    ];
    for text in bad {
        assert!(
            matches!(decode_cursor(&text), Err(ReadError::BadCursor)),
            "{}",
            text.chars().take(FIFTH * FIFTH).collect::<String>()
        );
    }
    Ok(())
}


fn hex(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}


#[tokio::test]
async fn a_cursor_walks_three_rows_of_one_baseline_one_at_a_time() -> TestResult {
    let fake = Fake::default();
    seed_three(&fake);
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let wanted = filter(Some("fail"), Some("base"));
    let first = list_state(&exec, &scope, &wanted, None, 1).await?;
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.rows.first().map(|row| row.asset.as_str()), Some("host-a"));
    let cursor_one = decode_cursor(&first.next_cursor.ok_or("no cursor")?)?;
    assert_eq!(cursor_one, key("base", "c1", "host-a"));
    let second = list_state(&exec, &scope, &wanted, Some(&cursor_one), 1).await?;
    assert_eq!(
        second.rows.first().map(|row| (row.control.as_str(), row.asset.as_str())),
        Some(("c1", "host-b"))
    );
    let cursor_two = decode_cursor(&second.next_cursor.ok_or("no cursor")?)?;
    let third = list_state(&exec, &scope, &wanted, Some(&cursor_two), 1).await?;
    assert_eq!(third.rows.first().map(|row| row.control.as_str()), Some("c2"));
    assert_eq!(third.next_cursor, None);
    assert!(recorded(&fake)
        .iter()
        .all(|(tenant, sql)| tenant == TENANT && *sql == LIST_VERDICT_BASELINE_SQL));
    Ok(())
}


#[tokio::test]
async fn every_filter_variant_reads_only_the_tenant_rows_it_names() -> TestResult {
    let fake = Fake::default();
    seed_three(&fake);
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let failed = list_state(&exec, &scope, &filter(Some("fail"), None), None, MAX_PAGE).await?;
    assert_eq!(failed.rows.len(), THIRD);
    let everything = list_state(&exec, &scope, &filter(None, None), None, MAX_PAGE).await?;
    assert_eq!(everything.rows.len(), FIVE);
    let one_baseline = list_state(&exec, &scope, &filter(None, Some("other")), None, MAX_PAGE).await?;
    assert_eq!(one_baseline.rows.len(), 1);
    let errors = list_state(&exec, &scope, &filter(Some("error"), None), None, MAX_PAGE).await?;
    assert_eq!(errors.rows.first().map(|row| row.verdict.as_str()), Some("error"));
    assert_eq!(errors.rows.first().and_then(|row| row.first_failed_micros), None);
    let foreign = list_state(&exec, &tenant_scope(OTHER)?, &filter(None, None), None, MAX_PAGE).await?;
    assert_eq!(foreign.rows.len(), 1);
    let sqls: Vec<&str> = recorded(&fake).iter().map(|(_tenant, sql)| *sql).collect();
    assert_eq!(
        sqls,
        [LIST_VERDICT_SQL, LIST_ALL_SQL, LIST_ALL_BASELINE_SQL, LIST_VERDICT_SQL, LIST_ALL_SQL]
    );
    Ok(())
}


const FIVE: usize = 5;


#[tokio::test]
async fn a_page_reads_one_row_past_the_limit_and_never_more() -> TestResult {
    let fake = Fake::default();
    seed_three(&fake);
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let exact = list_state(&exec, &scope, &filter(Some("fail"), None), None, THIRD).await?;
    assert_eq!((exact.rows.len(), exact.next_cursor), (THIRD, None));
    let short = list_state(&exec, &scope, &filter(Some("fail"), None), None, SECOND).await?;
    assert_eq!(short.rows.len(), SECOND);
    assert!(short.next_cursor.is_some());
    Ok(())
}


#[tokio::test]
async fn a_bad_row_is_served_around_and_the_cursor_is_the_raw_last_key() -> TestResult {
    let fake = Fake::default();
    put(&fake, TENANT, ("base", "c1", "a1"), ("fail", FAILED, SEEN));
    put(&fake, TENANT, ("base", "c2", "a1"), ("weird", "", SEEN));
    put(&fake, TENANT, ("base", "c3", "a1"), ("fail", FAILED, SEEN));
    put(&fake, TENANT, ("base", "c4", "a1"), ("pass", FAILED, SEEN));
    put(&fake, TENANT, ("base", "c5", "a1"), ("fail", "", SEEN));
    put(&fake, TENANT, ("base", "c6", "a1"), ("fail", "x", SEEN));
    put(&fake, TENANT, ("base", "c7", "a1"), ("pass", "", "x"));
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let middle = list_state(&exec, &scope, &filter(None, None), None, THIRD).await?;
    assert_eq!((middle.rows.len(), middle.skipped), (SECOND, 1));
    let last_bad = list_state(&exec, &scope, &filter(None, None), None, FOURTH).await?;
    assert_eq!((last_bad.rows.len(), last_bad.skipped), (SECOND, SECOND));
    assert_eq!(decode_cursor(&last_bad.next_cursor.ok_or("no cursor")?)?, key("base", "c4", "a1"));
    let only_bad = list_state(&exec, &scope, &filter(None, None), Some(&key("base", "c3", "a1")), THIRD).await?;
    assert_eq!((only_bad.rows.len(), only_bad.skipped), (0, THIRD));
    let cursor = decode_cursor(&only_bad.next_cursor.ok_or("no cursor")?)?;
    assert_eq!(cursor, key("base", "c6", "a1"));
    let rest = list_state(&exec, &scope, &filter(None, None), Some(&cursor), THIRD).await?;
    assert_eq!((rest.rows.len(), rest.skipped, rest.next_cursor), (0, 1, None));
    Ok(())
}


#[tokio::test]
async fn skipped_rows_are_logged_by_count_only() -> TestResult {
    let capture = Capture::default();
    let fake = Fake::default();
    put(&fake, TENANT, ("base", "c1", "SECRETHOST"), ("weird", "", SEEN));
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let guard = tracing::dispatcher::set_default(&capture_dispatch(&capture));
    let page = list_state(&exec, &scope, &filter(None, None), None, THIRD).await?;
    drop(guard);
    assert_eq!(page.skipped, 1);
    let text = captured(&capture);
    assert!(text.contains("skipped=1"), "{text}");
    assert!(!text.contains("SECRETHOST") && !text.contains("weird"), "{text}");
    Ok(())
}


#[tokio::test]
async fn a_key_outside_the_grammar_or_a_short_row_is_a_stored_value_failure() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let row = |cells: [&str; SIXTH]| cells.map(str::to_owned).to_vec();
    fake.state.lock().map_err(|_poisoned| "poisoned")?.forced = Some(vec![row(["-bad", "c1", "a1", "pass", "", SEEN])]);
    assert!(matches!(
        list_state(&exec, &scope, &filter(None, None), None, THIRD).await,
        Err(ReadError::BadKey)
    ));
    fake.state.lock().map_err(|_poisoned| "poisoned")?.forced = Some(vec![vec!["base".to_owned()]]);
    assert!(matches!(
        list_state(&exec, &scope, &filter(None, None), None, THIRD).await,
        Err(ReadError::BadRow)
    ));
    assert!(matches!(asset_state(&exec, &scope, "a1").await, Err(ReadError::BadRow)));
    Ok(())
}


#[tokio::test]
async fn a_limit_outside_one_to_the_page_maximum_is_refused_before_any_io() -> TestResult {
    let fake = Fake::default();
    seed_three(&fake);
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    for limit in [0, MAX_PAGE + 1] {
        assert!(matches!(
            list_state(&exec, &scope, &filter(None, None), None, limit).await,
            Err(ReadError::BadPageSize { limit: MAX_PAGE })
        ));
    }
    assert!(recorded(&fake).is_empty());
    assert!(matches!(limit_text(usize::MAX), Err(ReadError::BadLimit)));
    assert_eq!(limit_text(MAX_PAGE)?, "500");
    Ok(())
}


#[tokio::test]
async fn a_store_failure_is_a_database_error() -> TestResult {
    let fake = Fake {
        fail: true,
        ..Fake::default()
    };
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    assert!(matches!(
        list_state(&exec, &scope, &filter(None, None), None, 1).await,
        Err(ReadError::Pg(_))
    ));
    assert!(matches!(asset_state(&exec, &scope, "a1").await, Err(ReadError::Pg(_))));
    Ok(())
}


#[tokio::test]
async fn an_asset_lists_its_results_for_the_tenant_only() -> TestResult {
    let fake = Fake::default();
    seed_three(&fake);
    put(&fake, OTHER, ("base", "c9", "host-a"), ("fail", FAILED, SEEN));
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let found = asset_state(&exec, &scope, "host-a").await?.ok_or("none")?;
    let controls: Vec<&str> = found.rows.iter().map(|row| row.control.as_str()).collect();
    assert_eq!(controls, ["c1", "c2", "c3", "c1"]);
    assert_eq!((found.skipped, found.truncated), (0, false));
    assert!(asset_state(&exec, &scope, "host-z").await?.is_none());
    assert!(asset_state(&exec, &tenant_scope(OTHER)?, "host-z").await?.is_some());
    assert_eq!(recorded(&fake).len(), THIRD);
    Ok(())
}


#[tokio::test]
async fn a_malformed_asset_costs_no_statement() -> TestResult {
    let fake = Fake::default();
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let long = "a".repeat(MAX_ASSET_CHARS + 1);
    for asset in ["", "-a", "a b", "a%00", long.as_str(), "h\u{212a}"] {
        assert!(asset_state(&exec, &scope, asset).await?.is_none(), "{asset}");
    }
    assert!(recorded(&fake).is_empty());
    Ok(())
}


#[tokio::test]
async fn more_results_than_the_maximum_are_truncated_and_skips_are_counted() -> TestResult {
    let fake = Fake::default();
    (0..=MAX_ASSET_RESULTS).for_each(|index| put(&fake, TENANT, ("base", &format!("c{index:05}"), "host-a"), ("pass", "", SEEN)));
    let exec = executor(&fake);
    let scope = tenant_scope(TENANT)?;
    let found = asset_state(&exec, &scope, "host-a").await?.ok_or("none")?;
    assert_eq!((found.rows.len(), found.truncated), (MAX_ASSET_RESULTS, true));
    put(&fake, TENANT, ("base", "z-bad", "host-b"), ("weird", "", SEEN));
    let skipped = asset_state(&exec, &scope, "host-b").await?.ok_or("none")?;
    assert_eq!((skipped.rows.len(), skipped.skipped, skipped.truncated), (0, 1, false));
    Ok(())
}


#[test]
fn the_pure_helpers_apply_the_grammar() -> TestResult {
    assert!(is_asset("host/a:b@c~1^2+3") && !is_asset("^a") && !is_asset("a\0b"));
    assert!(key_ok("base", "c1", "a") && !key_ok("-base", "c1", "a") && !key_ok("base", "c1", "-a"));
    let sample = key("base", "c1", "a");
    assert!(stored_of(&sample, "fail", FAILED, SEEN).is_some());
    assert!(stored_of(&sample, "pass", "", SEEN).is_some());
    assert!(stored_of(&sample, "pass", FAILED, SEEN).is_none());
    assert!(stored_of(&sample, "fail", "", SEEN).is_none());
    assert!(stored_of(&sample, "pass", "x", SEEN).is_none());
    assert!(stored_of(&sample, "pass", "", "x").is_none());
    assert!(stored_of(&sample, "nope", "", SEEN).is_none());
    let row: Vec<String> = ["base", "c1", "a", "pass", "", SEEN].map(str::to_owned).to_vec();
    assert!(parse_row(&row)?.1.is_some());
    Ok(())
}


#[test]
fn each_filter_picks_its_statement_and_parameter_order() -> TestResult {
    let start = key("b", "c", "a");
    let fetch = || "51".to_owned();
    let strings = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect::<Vec<String>>();
    assert_eq!(
        statement_of(&filter(Some("fail"), None), &start, fetch()),
        (LIST_VERDICT_SQL, strings(&["fail", "b", "c", "a", "51"]))
    );
    assert_eq!(
        statement_of(&filter(Some("fail"), Some("x")), &start, fetch()),
        (LIST_VERDICT_BASELINE_SQL, strings(&["fail", "b", "c", "a", "51", "x"]))
    );
    assert_eq!(
        statement_of(&filter(None, None), &start, fetch()),
        (LIST_ALL_SQL, strings(&["b", "c", "a", "51"]))
    );
    assert_eq!(
        statement_of(&filter(None, Some("x")), &start, fetch()),
        (LIST_ALL_BASELINE_SQL, strings(&["b", "c", "a", "51", "x"]))
    );
    assert!(ASSET_SQL.contains("asset = $2"));
    Ok(())
}
