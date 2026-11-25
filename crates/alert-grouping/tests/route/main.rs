mod fixture;
mod http;
mod types;


use alert_grouping::model::GroupLimits;
use alert_grouping::route::{
    alert_groups_access, alert_groups_document, groups_flow, DEFAULT_PLAN, GROUPS_PATH, GROUP_READS_AT_ONCE, GROUP_READ_PAGES,
};
use alert_grouping::view::{GroupRoute, ReadPlan};
use alerts::error::StoreError;
use alerts::model::{Alert, AlertPage, Page};
use alerts::store::MAX_PAGE_SIZE;
use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::Response;
use core_api::model::{ApiError, ApiIdentity};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use fixture::{alert, backend_of, chunked, fixture, list_of, numbered, page_of, ANALYST, BASE_TIME, OTHER_TENANT, READER, TENANT};
use http::{body_json, get, login};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use types::{Served, TestResult};


const ONE_SECOND_MICROS: u64 = 1_000_000;


const BODY_LIMIT: usize = 4_194_304;


const ELEVEN_PAGES: usize = 1_100;


const FULL_READ: usize = 1_000;


const OVER_BY_ONE: usize = 1_001;


const SLOW_PAGE_SECONDS: u64 = 11;


const SMALL_PLAN_WINDOW: u64 = 100;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


const FIVE_SECONDS: u64 = 5;


const LATE_SECONDS: u64 = 30;


const MIDDLE_SECONDS: u64 = 20;


const EARLY_SECONDS: u64 = 10;


const THIRD_PAGE: usize = 2;


fn lock(mutex: &Mutex<Vec<TenantScope>>) -> MutexGuard<'_, Vec<TenantScope>> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


fn lock_failure(slot: &Mutex<Option<StoreError>>) -> Option<StoreError> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}


fn served(pages: Vec<AlertPage>) -> Served {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let shared = Arc::new(pages);
    let list = list_of(move |_scope, _page| {
        let index = counted.fetch_add(1, Ordering::SeqCst);
        let page = shared.get(index).cloned().unwrap_or_else(|| page_of(Vec::new(), false));
        Box::pin(async move { Ok(page) })
    });
    (list, calls)
}


fn groups(json: &Value) -> Result<&Vec<Value>, types::TestError> {
    Ok(json.get("groups").and_then(Value::as_array).ok_or("no groups")?)
}


fn field<'a>(json: &'a Value, name: &str) -> Result<&'a Value, types::TestError> {
    Ok(json.get(name).ok_or("missing field")?)
}


fn identity(tenant: &str) -> ApiIdentity {
    ApiIdentity {
        module: "alerts".to_owned(),
        tenant: tenant.to_owned(),
        generation: 1,
    }
}


fn plan_of(max_pages: usize, max_alerts: usize, max_groups: usize) -> ReadPlan {
    ReadPlan {
        limits: GroupLimits {
            window_micros: SMALL_PLAN_WINDOW,
            max_alerts,
            max_groups,
            max_alerts_per_group: DEFAULT_PLAN.limits.max_alerts_per_group,
        },
        max_pages,
        deadline: DEFAULT_PLAN.deadline,
    }
}


async fn flow_json(list: alerts::types::ListFn, plan: &ReadPlan) -> Result<Value, types::TestError> {
    let route = GroupRoute {
        backend: backend_of(list),
        reads: Arc::new(Semaphore::new(GROUP_READS_AT_ONCE)),
    };
    let response: Response = groups_flow(&identity(TENANT), &route, plan, Ok(()))
        .await
        .map_err(|error| format!("{error:?}"))?;
    let bytes = to_bytes(response.into_body(), BODY_LIMIT).await?;
    Ok(serde_json::from_slice(&bytes)?)
}


async fn flow_error(list: alerts::types::ListFn, plan: &ReadPlan, tenant: &str) -> Option<ApiError> {
    let route = GroupRoute {
        backend: backend_of(list),
        reads: Arc::new(Semaphore::new(GROUP_READS_AT_ONCE)),
    };
    groups_flow(&identity(tenant), &route, plan, Ok(())).await.err()
}


async fn analyst_get(fx: &fixture::Fixture, path: &str) -> Result<Response, types::TestError> {
    let token = login(&fx.router, ANALYST).await?;
    get(&fx.router, path, Some(&token)).await
}


#[tokio::test]
async fn no_session_is_401_no_permission_403_and_a_query_400_before_any_store_call() -> TestResult {
    let (list, calls) = served(vec![page_of(numbered(TENANT, "r1", TWO), false)]);
    let fx = fixture(TENANT, backend_of(list))?;
    assert_eq!(get(&fx.router, GROUPS_PATH, None).await?.status(), StatusCode::UNAUTHORIZED);
    let reader = login(&fx.router, READER).await?;
    assert_eq!(get(&fx.router, GROUPS_PATH, Some(&reader)).await?.status(), StatusCode::FORBIDDEN);
    let analyst = login(&fx.router, ANALYST).await?;
    for query in ["x=1", "tenant=globex", "limit=5"] {
        let refused = get(&fx.router, &format!("{GROUPS_PATH}?{query}"), Some(&analyst)).await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{query}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(get(&fx.router, GROUPS_PATH, Some(&analyst)).await?.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test]
async fn a_group_spans_page_boundaries_and_the_output_keeps_the_library_order() -> TestResult {
    let late = BASE_TIME + LATE_SECONDS * ONE_SECOND_MICROS;
    let middle = BASE_TIME + MIDDLE_SECONDS * ONE_SECOND_MICROS;
    let early = BASE_TIME + EARLY_SECONDS * ONE_SECOND_MICROS;
    let first = vec![alert(TENANT, "a5", "r1", &["e5"], late), alert(TENANT, "a4", "r2", &["e4"], late - 1)];
    let second = vec![alert(TENANT, "a3", "r1", &["e3"], middle)];
    let third = vec![alert(TENANT, "a2", "r1", &["e2"], early), alert(TENANT, "a1", "r2", &["e1"], early - 1)];
    let (list, calls) = served(vec![page_of(first, true), page_of(second, true), page_of(third, false)]);
    let fx = fixture(TENANT, backend_of(list))?;
    let json = body_json(analyst_get(&fx, GROUPS_PATH).await?).await?;
    assert_eq!(calls.load(Ordering::SeqCst), THREE);
    assert_eq!(field(&json, "complete")?, &Value::Bool(true));
    assert_eq!(field(&json, "alerts_read")?, FIVE);
    let listed = groups(&json)?;
    assert_eq!(listed.len(), TWO);
    let rules: Vec<&str> = listed.iter().filter_map(|group| group.get("rule_id").and_then(Value::as_str)).collect();
    assert_eq!(rules, ["r2", "r1"]);
    let spanning = listed.get(1).ok_or("no second group")?;
    assert_eq!(field(spanning, "alert_count")?, THREE);
    assert_eq!(field(spanning, "cut_at_older")?, &Value::Bool(false));
    assert!(spanning.get("tenant").is_none());
    assert_eq!(field(spanning, "first_time")?, "2023-11-14T22:13:30Z");
    Ok(())
}


#[tokio::test]
async fn eleven_pages_available_read_exactly_ten_and_say_so() -> TestResult {
    let (list, calls) = served(chunked(&numbered(TENANT, "r1", ELEVEN_PAGES)));
    let fx = fixture(TENANT, backend_of(list))?;
    let json = body_json(analyst_get(&fx, GROUPS_PATH).await?).await?;
    assert_eq!(calls.load(Ordering::SeqCst), GROUP_READ_PAGES);
    assert_eq!(field(&json, "complete")?, &Value::Bool(false));
    assert_eq!(field(&json, "alerts_read")?, FULL_READ);
    let only = groups(&json)?.first().ok_or("no group")?;
    assert_eq!(field(only, "alert_count")?, FULL_READ);
    assert_eq!(field(only, "omitted")?, &Value::Bool(true));
    assert_eq!(
        field(only, "alert_ids")?.as_array().map(Vec::len),
        Some(DEFAULT_PLAN.limits.max_alerts_per_group)
    );
    assert_eq!(field(only, "cut_at_older")?, &Value::Bool(true));
    assert_eq!(field(&json, "oldest_read")?, "2023-11-14T22:13:20Z");
    Ok(())
}


#[tokio::test]
async fn exactly_the_read_limit_is_complete_and_one_more_is_not() -> TestResult {
    let (exact, exact_calls) = served(chunked(&numbered(TENANT, "r1", FULL_READ)));
    let fx = fixture(TENANT, backend_of(exact))?;
    let json = body_json(analyst_get(&fx, GROUPS_PATH).await?).await?;
    assert_eq!(field(&json, "complete")?, &Value::Bool(true));
    assert_eq!(field(&json, "alerts_read")?, FULL_READ);
    assert_eq!(exact_calls.load(Ordering::SeqCst), GROUP_READ_PAGES);
    let (over, _calls) = served(chunked(&numbered(TENANT, "r1", OVER_BY_ONE)));
    let other = fixture(TENANT, backend_of(over))?;
    let exceeded = body_json(analyst_get(&other, GROUPS_PATH).await?).await?;
    assert_eq!(field(&exceeded, "complete")?, &Value::Bool(false));
    assert_eq!(field(&exceeded, "alerts_read")?, FULL_READ);
    Ok(())
}


#[test]
fn the_alert_cap_equals_the_pages_times_the_page_size() -> TestResult {
    assert_eq!(DEFAULT_PLAN.limits.max_alerts, GROUP_READ_PAGES * MAX_PAGE_SIZE);
    assert_eq!(DEFAULT_PLAN.limits.max_alerts, FULL_READ);
    assert_eq!(DEFAULT_PLAN.max_pages, GROUP_READ_PAGES);
    Ok(())
}


#[tokio::test]
async fn a_store_error_on_page_two_returns_the_alerts_reply_and_nothing_partial() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let list = list_of(move |_scope, _page| {
        let index = counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match index {
                0 => Ok(page_of(numbered(TENANT, "r1", TWO), true)),
                1 => Err(StoreError::Busy),
                _ => Err(StoreError::Pg(PgError::ConnectTimeout { seconds: FIVE_SECONDS })),
            }
        })
    });
    let fx = fixture(TENANT, backend_of(list))?;
    let busy = analyst_get(&fx, GROUPS_PATH).await?;
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(body_json(busy).await?.get("groups").is_none());
    assert_eq!(calls.load(Ordering::SeqCst), TWO);
    let failing = list_of(|_scope, page| {
        Box::pin(async move {
            page.after.map_or_else(
                || Ok(page_of(numbered(TENANT, "r1", TWO), true)),
                |_cursor| Err(StoreError::BadRow { column: 1 }),
            )
        })
    });
    let broken = fixture(TENANT, backend_of(failing))?;
    let failed = analyst_get(&broken, GROUPS_PATH).await?;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let timeout = list_of(|_scope, _page| Box::pin(async { Err(StoreError::Pg(PgError::ConnectTimeout { seconds: FIVE_SECONDS })) }));
    let slow = fixture(TENANT, backend_of(timeout))?;
    let unavailable = analyst_get(&slow, GROUPS_PATH).await?;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(unavailable).await?.get("error").and_then(|error| error.get("code")),
        Some(&Value::from("unavailable"))
    );
    Ok(())
}


#[tokio::test]
async fn the_scope_passed_to_the_store_is_the_identity_tenant_for_two_identities() -> TestResult {
    let seen: Arc<Mutex<Vec<TenantScope>>> = Arc::new(Mutex::new(Vec::new()));
    let record = |sink: Arc<Mutex<Vec<TenantScope>>>| {
        list_of(move |scope, _page: Page| {
            lock(&sink).push(scope);
            Box::pin(async { Ok(page_of(Vec::new(), false)) })
        })
    };
    let acme = fixture(TENANT, backend_of(record(Arc::clone(&seen))))?;
    let globex = fixture(OTHER_TENANT, backend_of(record(Arc::clone(&seen))))?;
    assert_eq!(analyst_get(&acme, GROUPS_PATH).await?.status(), StatusCode::OK);
    assert_eq!(analyst_get(&globex, GROUPS_PATH).await?.status(), StatusCode::OK);
    assert_eq!(*lock(&seen), [tenant_scope(TENANT)?, tenant_scope(OTHER_TENANT)?]);
    Ok(())
}


#[tokio::test]
async fn a_third_group_read_is_429_without_a_store_call_and_a_slot_frees_when_one_ends() -> TestResult {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let gate = Arc::new(Semaphore::new(0));
    let held = Arc::clone(&gate);
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
    let list = list_of(move |_scope, _page| {
        let index = counted.fetch_add(1, Ordering::SeqCst);
        let waiting = (index < GROUP_READS_AT_ONCE).then(|| Arc::clone(&held));
        let signal = entered_tx.clone();
        Box::pin(async move {
            signal.send(()).map_err(|_closed| StoreError::Busy)?;
            if let Some(blocker) = waiting {
                blocker.acquire().await.map_err(|_closed| StoreError::Busy)?.forget();
            }
            Ok(page_of(Vec::new(), false))
        })
    });
    let fx = fixture(TENANT, backend_of(list))?;
    let token = login(&fx.router, ANALYST).await?;
    let spawn_read = || {
        let router = fx.router.clone();
        let bearer = token.clone();
        tokio::spawn(async move {
            get(&router, GROUPS_PATH, Some(&bearer))
                .await
                .map(|response| response.status())
                .map_err(|error| error.to_string())
        })
    };
    let first = spawn_read();
    let second = spawn_read();
    entered_rx.recv().await.ok_or("first read never started")?;
    entered_rx.recv().await.ok_or("second read never started")?;
    let refused = get(&fx.router, GROUPS_PATH, Some(&token)).await?;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(calls.load(Ordering::SeqCst), GROUP_READS_AT_ONCE);
    gate.add_permits(GROUP_READS_AT_ONCE + 1);
    assert_eq!(first.await?, Ok(StatusCode::OK));
    assert_eq!(second.await?, Ok(StatusCode::OK));
    assert_eq!(get(&fx.router, GROUPS_PATH, Some(&token)).await?.status(), StatusCode::OK);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_deadline_passed_during_page_three_still_awaits_it_then_answers_503_without_page_four() -> TestResult {
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let (began, ended) = (Arc::clone(&started), Arc::clone(&finished));
    let list = list_of(move |_scope, _page| {
        let index = began.fetch_add(1, Ordering::SeqCst);
        let done = Arc::clone(&ended);
        Box::pin(async move {
            if index == THIRD_PAGE {
                tokio::time::sleep(Duration::from_secs(SLOW_PAGE_SECONDS)).await;
            }
            done.fetch_add(1, Ordering::SeqCst);
            Ok(page_of(numbered(TENANT, "r1", TWO), true))
        })
    });
    let fx = fixture(TENANT, backend_of(list))?;
    let response = analyst_get(&fx, GROUPS_PATH).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_json(response).await?.get("groups").is_none());
    assert_eq!(started.load(Ordering::SeqCst), THREE);
    assert_eq!(finished.load(Ordering::SeqCst), THREE);
    Ok(())
}


fn boundary_alerts(window: u64) -> Vec<Alert> {
    vec![
        alert(TENANT, "a3", "r_b", &["e3"], BASE_TIME + window + 1),
        alert(TENANT, "a2", "r_a", &["e2"], BASE_TIME + window),
        alert(TENANT, "a1", "r_o", &["e1"], BASE_TIME),
    ]
}


fn cut_flags(json: &Value) -> Result<Vec<(String, bool)>, types::TestError> {
    groups(json)?
        .iter()
        .map(|group| {
            let rule = field(group, "rule_id")?.as_str().ok_or("rule")?.to_owned();
            let flag = field(group, "cut_at_older")?.as_bool().ok_or("flag")?;
            Ok((rule, flag))
        })
        .collect()
}


#[tokio::test]
async fn cut_at_older_is_set_within_one_window_of_the_oldest_read_and_only_when_incomplete() -> TestResult {
    let plan = plan_of(1, SMALL_PLAN_WINDOW as usize, SMALL_PLAN_WINDOW as usize);
    let alerts = boundary_alerts(SMALL_PLAN_WINDOW);
    let cut = alerts.clone();
    let (incomplete, _calls) = served(vec![page_of(cut, true)]);
    let json = flow_json(incomplete, &plan).await?;
    assert_eq!(field(&json, "complete")?, &Value::Bool(false));
    let mut flags = cut_flags(&json)?;
    flags.sort();
    assert_eq!(flags, [("r_a".to_owned(), true), ("r_b".to_owned(), false), ("r_o".to_owned(), true)]);
    let (whole, _whole_calls) = served(vec![page_of(alerts, false)]);
    let finished = flow_json(whole, &plan).await?;
    assert_eq!(field(&finished, "complete")?, &Value::Bool(true));
    assert!(cut_flags(&finished)?.iter().all(|(_rule, flag)| !flag));
    Ok(())
}


#[tokio::test]
async fn an_empty_incomplete_read_has_no_groups_and_no_oldest() -> TestResult {
    let plan = plan_of(1, 1, 1);
    let (list, _calls) = served(vec![AlertPage {
        alerts: Vec::new(),
        next: fixture::cursor_after(&numbered(TENANT, "r1", 1)),
    }]);
    let json = flow_json(list, &plan).await?;
    assert_eq!(field(&json, "complete")?, &Value::Bool(false));
    assert_eq!(field(&json, "oldest_read")?, &Value::Null);
    assert_eq!(groups(&json)?.len(), 0);
    Ok(())
}


#[tokio::test]
async fn duplicates_are_counted_with_the_group() -> TestResult {
    let alerts = vec![
        alert(TENANT, "a2", "r1", &["e1", "e2"], BASE_TIME + 1),
        alert(TENANT, "a1", "r1", &["e2", "e1"], BASE_TIME),
    ];
    let (list, _calls) = served(vec![page_of(alerts, false)]);
    let json = flow_json(list, &DEFAULT_PLAN).await?;
    let only = groups(&json)?.first().ok_or("no group")?;
    assert_eq!(field(only, "duplicates")?, 1);
    assert_eq!(field(only, "alert_count")?, TWO);
    assert_eq!(field(only, "max_severity")?, "high");
    assert_eq!(field(only, "representative")?, "a1");
    Ok(())
}


#[tokio::test]
async fn an_out_of_range_created_time_is_a_500() -> TestResult {
    let broken = alert(TENANT, "a1", "r1", &["e1"], u64::MAX);
    let (list, _calls) = served(vec![page_of(vec![broken], false)]);
    let fx = fixture(TENANT, backend_of(list))?;
    let response = analyst_get(&fx, GROUPS_PATH).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}


#[tokio::test]
async fn the_grouping_limits_and_a_bad_tenant_are_a_fixed_500_through_the_flow() -> TestResult {
    let two_rules = || {
        let alerts = vec![
            alert(TENANT, "a2", "r2", &["e2"], BASE_TIME + 1),
            alert(TENANT, "a1", "r1", &["e1"], BASE_TIME),
        ];
        served(vec![page_of(alerts, false)]).0
    };
    assert_eq!(flow_error(two_rules(), &plan_of(1, TWO, 1), TENANT).await, Some(ApiError::Internal));
    assert_eq!(flow_error(two_rules(), &plan_of(1, 1, TWO), TENANT).await, Some(ApiError::Internal));
    let (never, calls) = served(Vec::new());
    assert_eq!(flow_error(never, &DEFAULT_PLAN, "-x").await, Some(ApiError::Internal));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(flow_error(two_rules(), &plan_of(1, TWO, TWO), TENANT).await, None);
    Ok(())
}


#[tokio::test]
async fn a_refused_query_is_the_400_through_the_flow() -> TestResult {
    let route = GroupRoute {
        backend: backend_of(served(Vec::new()).0),
        reads: Arc::new(Semaphore::new(GROUP_READS_AT_ONCE)),
    };
    let refused = groups_flow(&identity(TENANT), &route, &DEFAULT_PLAN, Err(ApiError::BadRequest)).await;
    assert_eq!(refused.err(), Some(ApiError::BadRequest));
    Ok(())
}


#[test]
fn the_route_needs_alerts_read_and_is_in_the_document() -> TestResult {
    let table = alert_groups_access();
    assert_eq!(table.keys().map(String::as_str).collect::<Vec<_>>(), ["GET /alert-groups"]);
    let document = serde_json::to_value(alert_groups_document())?;
    assert!(document.get("paths").and_then(|paths| paths.get(GROUPS_PATH)).is_some());
    assert!(serde_json::to_string(&table.values().map(|rule| format!("{:?}", rule.requirement)).collect::<Vec<_>>())?.contains("alerts.read"));
    Ok(())
}


#[tokio::test]
async fn a_cursor_or_size_refusal_from_the_store_is_a_500_never_the_callers_400() -> TestResult {
    for refusal in [StoreError::BadCursor, StoreError::BadPageSize { limit: MAX_PAGE_SIZE }] {
        let first = page_of(numbered(TENANT, "r1", TWO), true);
        let refused = Arc::new(Mutex::new(Some(refusal)));
        let list = list_of(move |_scope, page| {
            let failure = if page.after.is_some() { lock_failure(&refused) } else { None };
            let answer = failure.map_or_else(|| Ok(first.clone()), Err);
            Box::pin(async move { answer })
        });
        assert_eq!(flow_error(list, &DEFAULT_PLAN, TENANT).await, Some(ApiError::Internal));
    }
    Ok(())
}


#[tokio::test]
async fn the_chunked_helper_pages_by_the_store_page_size() -> TestResult {
    let pages = chunked(&numbered(TENANT, "r1", ELEVEN_PAGES));
    assert_eq!(pages.len(), GROUP_READ_PAGES + 1);
    assert!(pages
        .iter()
        .take(GROUP_READ_PAGES)
        .all(|page| page.next.is_some() && page.alerts.len() == MAX_PAGE_SIZE));
    Ok(())
}
