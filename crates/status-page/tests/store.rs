#[path = "common/types.rs"]
mod types;


use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use status_page::error::StoreError;
use status_page::model::{ComponentConfig, PageConfig, DEFAULT_LIMITS};
use status_page::render::render;
use status_page::store::{
    add_update, count_of, create_incident, published_incidents, read_published, resolve_incident, COUNTS_SQL, CREATE_SQL, MAX_DECLARED_SERVICES,
    MAX_MESSAGE_CHARACTERS, MAX_NOTE_CHARACTERS, MAX_PUBLISHED, MAX_SERVICE_CHARACTERS, MAX_TITLE_CHARACTERS, MAX_UPDATES_PER_INCIDENT,
    MAX_UPDATES_READ_PER_INCIDENT, MAX_UPDATE_BYTES_PER_TICK, MIGRATIONS, PUBLISHED_SQL, RESOLVE_SQL, UPDATES_SQL, UPDATE_SQL,
};
use status_page::store_model::{Cell, IncidentRef, NewIncident, Param, Statement};
use status_page::types::Row;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::future::{ready, Ready};
use std::rc::Rc;
use types::TestResult;


const TENANT_A: &str = "acme";


const SERVICE: &str = "svc-web-internal";


const PRIVATE: &str = "svc-private";


const TENANT_B: &str = "globex";


const SECRET_NOTE: &str = "internal 10.0.0.5 SECRET-NOTE";


const SECRET_UPDATE_NOTE: &str = "root cause SECRET-UPDATE-NOTE";


const KNOWN_KEYS: [&str; THREE] = ["(resolved_at IS NULL) DESC", "started_at DESC", "id DESC"];


const START: i64 = 1_700_000_000;


const LATER: i64 = 60;


const END: i64 = 120;


const THREE: usize = 3;


const FOUR: usize = 4;


const LIMIT_PARAM: usize = 5;


const TWO_I64: i64 = 2;


const TWO: usize = 2;


const OVER_LIMIT: u32 = 501;


const SMALL_LIMIT: u32 = 1;


struct StoredIncident {
    tenant: String,
    id: i64,
    service: String,
    title: String,
    published: bool,
    started_at: i64,
    resolved_at: Option<i64>,
    version: i64,
}


struct StoredUpdate {
    tenant: String,
    incident: i64,
    at: i64,
    message: String,
}


#[derive(Default)]
struct Db {
    incidents: Vec<StoredIncident>,
    updates: Vec<StoredUpdate>,
    log: Vec<Statement>,
}


fn bad(column: &'static str) -> StoreError {
    StoreError::BadRow { column }
}


fn int_param(params: &[Param], index: usize) -> Result<i64, StoreError> {
    match params.get(index) {
        Some(Param::Int(value)) => Ok(*value),
        _ => Err(bad("fake int")),
    }
}


fn text_param(params: &[Param], index: usize) -> Result<String, StoreError> {
    match params.get(index) {
        Some(Param::Text(value)) => Ok(value.clone()),
        _ => Err(bad("fake text")),
    }
}


fn bool_param(params: &[Param], index: usize) -> Result<bool, StoreError> {
    match params.get(index) {
        Some(Param::Bool(value)) => Ok(*value),
        _ => Err(bad("fake bool")),
    }
}


fn services_param(params: &[Param], index: usize) -> Result<Vec<String>, StoreError> {
    match params.get(index) {
        Some(Param::Texts(value)) => Ok(value.clone()),
        _ => Err(bad("fake texts")),
    }
}


fn declared() -> Vec<String> {
    vec![SERVICE.to_owned()]
}


fn int_cell(value: i64) -> Cell {
    Cell::Int(value)
}


fn text_cell(value: &str) -> Cell {
    Cell::Text(value.to_owned())
}


fn fake_create(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let id = i64::try_from(db.incidents.len()).map_err(|_overflow| bad("fake id"))? + 1;
    db.incidents.push(StoredIncident {
        tenant: tenant.to_owned(),
        id,
        service: text_param(params, 0)?,
        title: text_param(params, 1)?,
        published: bool_param(params, TWO)?,
        started_at: int_param(params, THREE)?,
        resolved_at: None,
        version: 0,
    });
    Ok(vec![vec![int_cell(id), int_cell(0)]])
}


fn fake_update(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let id = int_param(params, 0)?;
    let version = int_param(params, 1)?;
    let limit = int_param(params, LIMIT_PARAM)?;
    let count = db
        .updates
        .iter()
        .filter(|update| update.tenant == tenant && update.incident == id)
        .count();
    let within = i64::try_from(count).map_err(|_overflow| bad("fake count"))? < limit;
    let message = text_param(params, THREE)?;
    let at = int_param(params, TWO)?;
    let found = db
        .incidents
        .iter_mut()
        .find(|incident| incident.tenant == tenant && incident.id == id && incident.version == version && within);
    match found {
        Some(incident) => {
            incident.version += 1;
            let next = incident.version;
            db.updates.push(StoredUpdate {
                tenant: tenant.to_owned(),
                incident: id,
                at,
                message,
            });
            Ok(vec![vec![int_cell(id), int_cell(next)]])
        }
        None => Ok(Vec::new()),
    }
}


fn fake_resolve(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let id = int_param(params, 0)?;
    let version = int_param(params, 1)?;
    let at = int_param(params, TWO)?;
    let found = db
        .incidents
        .iter_mut()
        .find(|incident| incident.tenant == tenant && incident.id == id && incident.version == version && incident.resolved_at.is_none());
    match found {
        Some(incident) => {
            incident.version += 1;
            incident.resolved_at = Some(at);
            Ok(vec![vec![int_cell(id), int_cell(incident.version)]])
        }
        None => Ok(Vec::new()),
    }
}


fn order_keys(sql: &'static str) -> Result<Vec<&'static str>, StoreError> {
    let clause = sql
        .split("ORDER BY ")
        .nth(1)
        .and_then(|tail| tail.split(" LIMIT $2").next())
        .ok_or_else(|| bad("fake order"))?;
    let keys: Vec<&str> = clause.split(", ").collect();
    if keys.iter().all(|key| KNOWN_KEYS.contains(key)) {
        Ok(keys)
    } else {
        Err(bad("fake order key"))
    }
}


fn compare(keys: &[&str], left: &StoredIncident, right: &StoredIncident) -> Ordering {
    keys.iter().fold(Ordering::Equal, |so_far, key| {
        so_far.then_with(|| match *key {
            "(resolved_at IS NULL) DESC" => right.resolved_at.is_none().cmp(&left.resolved_at.is_none()),
            "started_at DESC" => right.started_at.cmp(&left.started_at),
            _ => right.id.cmp(&left.id),
        })
    })
}


fn on_declared(sql: &'static str, params: &[Param], index: usize, incident: &StoredIncident) -> Result<bool, StoreError> {
    let filtered = sql.contains(&format!("service = ANY(${})", index + TWO));
    Ok(!filtered || services_param(params, index)?.contains(&incident.service))
}


fn published_of<'db>(db: &'db Db, tenant: &str, sql: &'static str, params: &[Param], index: usize) -> Result<Vec<&'db StoredIncident>, StoreError> {
    db.incidents
        .iter()
        .filter(|incident| incident.tenant == tenant && incident.published)
        .filter_map(|incident| on_declared(sql, params, index, incident).map(|keep| keep.then_some(incident)).transpose())
        .collect()
}


fn newest_published<'db>(
    db: &'db Db,
    tenant: &str,
    sql: &'static str,
    params: &[Param],
    services_index: usize,
) -> Result<Vec<&'db StoredIncident>, StoreError> {
    let limit = usize::try_from(int_param(params, 0)?).map_err(|_overflow| bad("fake limit"))?;
    let keys = order_keys(sql)?;
    let mut shown = published_of(db, tenant, sql, params, services_index)?;
    shown.sort_by(|left, right| compare(&keys, left, right));
    shown.truncate(limit);
    Ok(shown)
}


fn update_count(db: &Db, tenant: &str, incident: i64) -> Result<i64, StoreError> {
    let count = db
        .updates
        .iter()
        .filter(|update| update.tenant == tenant && update.incident == incident)
        .count();
    i64::try_from(count).map_err(|_overflow| bad("fake update count"))
}


fn fake_published(db: &Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    newest_published(db, tenant, PUBLISHED_SQL, params, 1)?
        .iter()
        .map(|incident| {
            Ok(vec![
                int_cell(incident.id),
                text_cell(&incident.service),
                text_cell(&incident.title),
                int_cell(incident.started_at),
                incident.resolved_at.map_or(Cell::Null, int_cell),
                int_cell(update_count(db, tenant, incident.id)?),
            ])
        })
        .collect()
}


fn fake_counts(db: &Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let shown = published_of(db, tenant, COUNTS_SQL, params, 0)?;
    let ongoing = shown.iter().filter(|incident| incident.resolved_at.is_none()).count();
    let total = i64::try_from(shown.len()).map_err(|_overflow| bad("fake total"))?;
    let open = i64::try_from(ongoing).map_err(|_overflow| bad("fake ongoing"))?;
    Ok(vec![vec![int_cell(total), int_cell(open)]])
}


fn newest_updates<'db>(db: &'db Db, tenant: &str, incident: i64, cap: usize) -> Vec<&'db StoredUpdate> {
    let mut own: Vec<(usize, &StoredUpdate)> = db
        .updates
        .iter()
        .enumerate()
        .filter(|(_seq, update)| update.tenant == tenant && update.incident == incident)
        .collect();
    own.sort_by_key(|(seq, update)| std::cmp::Reverse((update.at, *seq)));
    own.into_iter().take(cap).map(|(_seq, update)| update).collect()
}


fn fake_updates(db: &Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let cap = usize::try_from(int_param(params, 1)?).map_err(|_overflow| bad("fake cap"))?;
    let budget = usize::try_from(int_param(params, TWO)?).map_err(|_overflow| bad("fake budget"))?;
    let mut running = 0;
    let mut rows: Vec<&StoredUpdate> = newest_published(db, tenant, UPDATES_SQL, params, THREE)?
        .iter()
        .flat_map(|incident| newest_updates(db, tenant, incident.id, cap))
        .take_while(|update| {
            running += update.message.len();
            running <= budget
        })
        .collect();
    rows.sort_by_key(|update| (update.incident, update.at));
    Ok(rows
        .iter()
        .map(|update| vec![int_cell(update.incident), int_cell(update.at), text_cell(&update.message)])
        .collect())
}


fn execute(db: &Rc<RefCell<Db>>, scope: &TenantScope, statement: Statement) -> Result<Vec<Row>, StoreError> {
    let mut state = db.try_borrow_mut().map_err(|_busy| bad("fake borrow"))?;
    state.log.push(statement.clone());
    let tenant = tenant_of(scope);
    match statement.sql {
        CREATE_SQL => fake_create(&mut state, tenant, &statement.params),
        UPDATE_SQL => fake_update(&mut state, tenant, &statement.params),
        RESOLVE_SQL => fake_resolve(&mut state, tenant, &statement.params),
        PUBLISHED_SQL => fake_published(&state, tenant, &statement.params),
        UPDATES_SQL => fake_updates(&state, tenant, &statement.params),
        COUNTS_SQL => fake_counts(&state, tenant, &statement.params),
        _ => Err(bad("fake sql")),
    }
}


fn executor(db: &Rc<RefCell<Db>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(db);
    move |scope: &TenantScope, statement: Statement| ready(execute(&shared, scope, statement))
}


fn new_incident(title: &str, published: bool, started_at: i64) -> NewIncident {
    NewIncident {
        service: SERVICE.to_owned(),
        title: title.to_owned(),
        published,
        started_at,
        internal_note: SECRET_NOTE.to_owned(),
    }
}


fn config() -> PageConfig {
    PageConfig {
        id: "main".to_owned(),
        tenant: TENANT_A.to_owned(),
        title: "Acme status".to_owned(),
        checks: Vec::new(),
        components: vec![ComponentConfig {
            name: "Website".to_owned(),
            service: SERVICE.to_owned(),
            objective_ppm: None,
            rule: None,
        }],
    }
}


#[test]
fn the_migration_is_valid_and_keys_every_table_by_tenant() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    let migration = MIGRATIONS.first().ok_or("no migration")?;
    assert!(migration.version.starts_with("status_"));
    assert!(migration.sql.contains("PRIMARY KEY (tenant, id)"));
    assert!(migration.sql.contains("PRIMARY KEY (tenant, seq)"));
    assert!(migration.sql.contains("FOREIGN KEY (tenant, incident)"));
    Ok(())
}


#[test]
fn the_second_migration_indexes_the_unresolved_first_order_of_the_public_reads() -> TestResult {
    let migration = MIGRATIONS.get(1).ok_or("no second migration")?;
    assert_eq!(migration.version, "status_0002");
    assert!(migration
        .sql
        .contains("(tenant, (resolved_at IS NULL) DESC, started_at DESC, id DESC) WHERE published"));
    [PUBLISHED_SQL, UPDATES_SQL].iter().for_each(|sql| {
        assert!(
            sql.contains("ORDER BY (resolved_at IS NULL) DESC, started_at DESC, id DESC LIMIT $2"),
            "{sql}"
        )
    });
    Ok(())
}


#[test]
fn every_statement_filters_on_the_tenant_bound_as_the_first_parameter() -> TestResult {
    [UPDATE_SQL, RESOLVE_SQL, PUBLISHED_SQL, UPDATES_SQL, COUNTS_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("tenant = $1"), "{sql}"));
    assert!(CREATE_SQL.contains("(tenant, ") && CREATE_SQL.contains("VALUES ($1, "));
    Ok(())
}


#[test]
fn the_public_statements_never_select_internal_columns() -> TestResult {
    [PUBLISHED_SQL, UPDATES_SQL, COUNTS_SQL].iter().for_each(|sql| {
        assert!(!sql.contains("internal_note"), "{sql}");
        assert!(!sql.contains("assignee"), "{sql}");
    });
    Ok(())
}


#[tokio::test]
async fn an_incident_is_created_updated_and_resolved_with_a_moving_version() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let created = create_incident(&mut exec, &scope, &new_incident("Website down", true, START)).await?;
    assert_eq!(created.version, 0);
    let updated = add_update(&mut exec, &scope, created, START + LATER, "Investigating", SECRET_UPDATE_NOTE).await?;
    assert_eq!((updated.id, updated.version), (created.id, 1));
    let resolved = resolve_incident(&mut exec, &scope, updated, START + END).await?;
    assert_eq!((resolved.id, resolved.version), (created.id, TWO_I64));
    let state = db.try_borrow()?;
    assert_eq!(state.incidents.first().map(|incident| incident.resolved_at), Some(Some(START + END)));
    Ok(())
}


#[tokio::test]
async fn a_stale_version_is_a_conflict_and_changes_nothing() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let created = create_incident(&mut exec, &scope, &new_incident("Website down", true, START)).await?;
    add_update(&mut exec, &scope, created, START, "first", "").await?;
    assert!(matches!(
        add_update(&mut exec, &scope, created, START, "second", "").await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        resolve_incident(&mut exec, &scope, created, END).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(db.try_borrow()?.updates.len(), 1);
    Ok(())
}


#[tokio::test]
async fn a_resolved_incident_cannot_be_resolved_again() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let created = create_incident(&mut exec, &scope, &new_incident("Website down", true, START)).await?;
    let resolved = resolve_incident(&mut exec, &scope, created, END).await?;
    assert!(matches!(
        resolve_incident(&mut exec, &scope, resolved, END).await,
        Err(StoreError::Conflict)
    ));
    Ok(())
}


#[tokio::test]
async fn the_update_count_of_an_incident_is_bounded() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let created = create_incident(&mut exec, &scope, &new_incident("Website down", true, START)).await?;
    let mut current = created;
    for i in 0..MAX_UPDATES_PER_INCIDENT {
        current = add_update(&mut exec, &scope, current, START + i, "progress", "").await?;
    }
    assert!(matches!(
        add_update(&mut exec, &scope, current, END, "one too many", "").await,
        Err(StoreError::Conflict)
    ));
    Ok(())
}


#[tokio::test]
async fn another_tenant_can_neither_change_nor_read_an_incident_with_the_same_id() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope_a = tenant_scope(TENANT_A)?;
    let scope_b = tenant_scope(TENANT_B)?;
    let created = create_incident(&mut exec, &scope_a, &new_incident("Website down", true, START)).await?;
    let foreign_own = create_incident(&mut exec, &scope_b, &new_incident("Globex outage", true, START)).await?;
    assert_eq!(foreign_own.id, TWO_I64);
    assert!(matches!(
        add_update(&mut exec, &scope_b, created, START, "hijack", "").await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        resolve_incident(&mut exec, &scope_b, created, END).await,
        Err(StoreError::Conflict)
    ));
    let probe = IncidentRef { id: created.id, version: 0 };
    assert!(matches!(
        resolve_incident(&mut exec, &scope_b, probe, END).await,
        Err(StoreError::Conflict)
    ));
    let seen_by_b = published_incidents(&mut exec, &scope_b, &declared(), MAX_PUBLISHED).await?;
    assert_eq!(seen_by_b.len(), 1);
    assert!(seen_by_b
        .iter()
        .all(|incident| incident.tenant == TENANT_B && incident.public_title == "Globex outage"));
    let state = db.try_borrow()?;
    let original = state.incidents.iter().find(|incident| incident.tenant == TENANT_A).ok_or("missing")?;
    assert_eq!((original.version, original.resolved_at), (0, None));
    assert!(state.updates.is_empty());
    Ok(())
}


#[tokio::test]
async fn published_incidents_hide_unpublished_ones_and_every_internal_note() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let shown = create_incident(&mut exec, &scope, &new_incident("Website down", true, START)).await?;
    create_incident(&mut exec, &scope, &new_incident("Draft", false, START + 1)).await?;
    let newer = create_incident(&mut exec, &scope, &new_incident("Mail slow", true, START + LATER)).await?;
    let first = add_update(&mut exec, &scope, shown, START + 1, "Investigating", SECRET_UPDATE_NOTE).await?;
    add_update(&mut exec, &scope, first, START + TWO_I64, "Fixing", "").await?;
    resolve_incident(&mut exec, &scope, newer, END).await?;
    let incidents = published_incidents(&mut exec, &scope, &declared(), MAX_PUBLISHED).await?;
    assert_eq!(incidents.len(), TWO);
    assert_eq!(
        incidents.iter().map(|incident| incident.public_title.as_str()).collect::<Vec<_>>(),
        ["Website down", "Mail slow"]
    );
    let ongoing = incidents.first().ok_or("missing")?;
    assert_eq!(ongoing.updates.len(), TWO);
    assert_eq!(incidents.get(1).map(|incident| incident.resolved_at), Some(Some(END)));
    assert!(incidents.iter().all(|incident| incident.published && incident.tenant == TENANT_A));
    let dump = format!("{incidents:?}");
    assert!(!dump.contains("SECRET"));
    assert!(incidents
        .iter()
        .all(|incident| incident.internal_note.is_empty() && incident.assignee.is_empty()));
    let state = db.try_borrow()?;
    let public_sql: Vec<&Statement> = state
        .log
        .iter()
        .filter(|statement| statement.sql == PUBLISHED_SQL || statement.sql == UPDATES_SQL)
        .collect();
    assert_eq!(public_sql.len(), TWO);
    let limit = Param::Int(i64::from(MAX_PUBLISHED));
    let services = Param::Texts(declared());
    assert_eq!(
        public_sql.first().map(|statement| statement.params.clone()),
        Some(vec![limit.clone(), services.clone()])
    );
    assert_eq!(
        public_sql.get(1).map(|statement| statement.params.clone()),
        Some(vec![
            limit,
            Param::Int(MAX_UPDATES_READ_PER_INCIDENT),
            Param::Int(MAX_UPDATE_BYTES_PER_TICK),
            services
        ])
    );
    Ok(())
}


#[tokio::test]
async fn the_limit_bounds_the_published_list() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    create_incident(&mut exec, &scope, &new_incident("Older", true, START)).await?;
    create_incident(&mut exec, &scope, &new_incident("Newer", true, START + END)).await?;
    let one = published_incidents(&mut exec, &scope, &declared(), SMALL_LIMIT).await?;
    assert_eq!(one.iter().map(|incident| incident.public_title.as_str()).collect::<Vec<_>>(), ["Newer"]);
    assert!(matches!(
        published_incidents(&mut exec, &scope, &declared(), 0).await,
        Err(StoreError::LimitOutOfRange { limit: 0, .. })
    ));
    assert!(matches!(
        published_incidents(&mut exec, &scope, &declared(), OVER_LIMIT).await,
        Err(StoreError::LimitOutOfRange {
            limit: OVER_LIMIT,
            max: MAX_PUBLISHED
        })
    ));
    Ok(())
}


#[tokio::test]
async fn the_page_rendered_from_the_store_shows_no_note_and_no_other_tenant() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope_a = tenant_scope(TENANT_A)?;
    let scope_b = tenant_scope(TENANT_B)?;
    let created = create_incident(&mut exec, &scope_a, &new_incident("Website down", true, START)).await?;
    add_update(&mut exec, &scope_a, created, START + 1, "Investigating", SECRET_UPDATE_NOTE).await?;
    create_incident(&mut exec, &scope_b, &new_incident("Globex outage", true, START)).await?;
    let incidents = published_incidents(&mut exec, &scope_a, &declared(), MAX_PUBLISHED).await?;
    let page = render(&config(), &[], &incidents, &[], END, &DEFAULT_LIMITS)?;
    assert!(page.json.contains("Website down") && page.json.contains("Investigating"));
    [&page.json, &page.html].iter().for_each(|text| {
        assert!(!text.contains("SECRET") && !text.contains("Globex") && !text.contains("10.0.0.5"));
    });
    Ok(())
}


#[tokio::test]
async fn text_over_its_bound_or_malformed_is_refused_before_any_statement() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let long = |count: usize| "a".repeat(count);
    let mut too_long_title = new_incident(&long(MAX_TITLE_CHARACTERS + 1), true, START);
    assert!(matches!(
        create_incident(&mut exec, &scope, &too_long_title).await,
        Err(StoreError::TextTooLong {
            field: "title",
            limit: MAX_TITLE_CHARACTERS
        })
    ));
    too_long_title.title = "\u{e9}".repeat(MAX_TITLE_CHARACTERS);
    create_incident(&mut exec, &scope, &too_long_title).await?;
    let mut service = new_incident("ok", true, START);
    service.service = long(MAX_SERVICE_CHARACTERS + 1);
    assert!(matches!(
        create_incident(&mut exec, &scope, &service).await,
        Err(StoreError::TextTooLong { field: "service", .. })
    ));
    service.service = "  ".to_owned();
    assert!(matches!(
        create_incident(&mut exec, &scope, &service).await,
        Err(StoreError::TextInvalid { field: "service" })
    ));
    let mut titled = new_incident("two\nlines", true, START);
    assert!(matches!(
        create_incident(&mut exec, &scope, &titled).await,
        Err(StoreError::TextInvalid { field: "title" })
    ));
    titled.title = String::new();
    assert!(matches!(
        create_incident(&mut exec, &scope, &titled).await,
        Err(StoreError::TextInvalid { field: "title" })
    ));
    titled.title = "ok".to_owned();
    titled.internal_note = long(MAX_NOTE_CHARACTERS + 1);
    assert!(matches!(
        create_incident(&mut exec, &scope, &titled).await,
        Err(StoreError::TextTooLong { field: "internal_note", .. })
    ));
    titled.internal_note = "bad\u{0}note".to_owned();
    assert!(matches!(
        create_incident(&mut exec, &scope, &titled).await,
        Err(StoreError::TextInvalid { field: "internal_note" })
    ));
    titled.internal_note = "line one\nline two".to_owned();
    let created = create_incident(&mut exec, &scope, &titled).await?;
    assert!(matches!(
        add_update(&mut exec, &scope, created, START, &long(MAX_MESSAGE_CHARACTERS + 1), "").await,
        Err(StoreError::TextTooLong {
            field: "message",
            limit: MAX_MESSAGE_CHARACTERS
        })
    ));
    assert!(matches!(
        add_update(&mut exec, &scope, created, START, "", "").await,
        Err(StoreError::TextInvalid { field: "message" })
    ));
    assert!(matches!(
        add_update(&mut exec, &scope, created, START, "ok", &long(MAX_NOTE_CHARACTERS + 1)).await,
        Err(StoreError::TextTooLong { field: "internal_note", .. })
    ));
    add_update(&mut exec, &scope, created, START, "two\nlines", "").await?;
    assert_eq!(db.try_borrow()?.log.len(), THREE);
    Ok(())
}


#[tokio::test]
async fn an_executor_error_is_returned_by_every_operation() -> TestResult {
    let scope = tenant_scope(TENANT_A)?;
    let mut failing = |_scope: &TenantScope, _statement: Statement| ready(Err::<Vec<Row>, StoreError>(bad("down")));
    let reference = IncidentRef { id: 1, version: 0 };
    assert!(matches!(
        create_incident(&mut failing, &scope, &new_incident("x", true, START)).await,
        Err(StoreError::BadRow { column: "down" })
    ));
    assert!(matches!(
        add_update(&mut failing, &scope, reference, START, "x", "").await,
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(
        resolve_incident(&mut failing, &scope, reference, START).await,
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(
        published_incidents(&mut failing, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { .. })
    ));
    Ok(())
}


fn canned(rows: Vec<Row>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    move |_scope: &TenantScope, _statement: Statement| ready(Ok(rows.clone()))
}


#[tokio::test]
async fn malformed_rows_are_refused_with_the_column_name() -> TestResult {
    let scope = tenant_scope(TENANT_A)?;
    let incident = new_incident("x", true, START);
    let mut empty = canned(Vec::new());
    assert!(matches!(
        create_incident(&mut empty, &scope, &incident).await,
        Err(StoreError::BadRow { column: "id" })
    ));
    let mut short = canned(vec![vec![int_cell(1)]]);
    assert!(matches!(
        create_incident(&mut short, &scope, &incident).await,
        Err(StoreError::BadRow { column: "version" })
    ));
    let mut text_id = canned(vec![vec![text_cell("1"), int_cell(0)]]);
    assert!(matches!(
        create_incident(&mut text_id, &scope, &incident).await,
        Err(StoreError::BadRow { column: "id" })
    ));
    let mut null_version = canned(vec![vec![int_cell(1), Cell::Null]]);
    assert!(matches!(
        resolve_incident(&mut null_version, &scope, IncidentRef { id: 1, version: 0 }, START).await,
        Err(StoreError::BadRow { column: "version" })
    ));
    Ok(())
}


#[tokio::test]
async fn malformed_public_rows_are_refused_with_the_column_name() -> TestResult {
    let scope = tenant_scope(TENANT_A)?;
    let good = vec![
        int_cell(1),
        text_cell("svc"),
        text_cell("title"),
        int_cell(START),
        Cell::Null,
        int_cell(0),
    ];
    let mut broken = |_scope: &TenantScope, statement: Statement| {
        let rows = match statement.sql {
            PUBLISHED_SQL => vec![good.clone()],
            _ => vec![vec![int_cell(1), int_cell(START), int_cell(1)]],
        };
        ready(Ok::<Vec<Row>, StoreError>(rows))
    };
    assert!(matches!(
        published_incidents(&mut broken, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "message" })
    ));
    let mut no_updates = |_scope: &TenantScope, statement: Statement| {
        let rows = match statement.sql {
            PUBLISHED_SQL => vec![good.clone()],
            _ => Vec::new(),
        };
        ready(Ok::<Vec<Row>, StoreError>(rows))
    };
    let incidents = published_incidents(&mut no_updates, &scope, &declared(), 1).await?;
    assert_eq!(
        incidents.first().map(|incident| (incident.resolved_at, incident.updates.len())),
        Some((None, 0))
    );
    let broken_columns: [(usize, Cell, &str); LIMIT_PARAM] = [
        (LIMIT_PARAM, int_cell(-1), "update_count"),
        (1, int_cell(1), "service"),
        (TWO, int_cell(1), "public_title"),
        (THREE, text_cell("x"), "started_at"),
        (FOUR, text_cell("x"), "resolved_at"),
    ];
    let short_row: Row = good.iter().take(LIMIT_PARAM).cloned().collect();
    let mut no_count = |_scope: &TenantScope, statement: Statement| {
        let rows = if statement.sql == PUBLISHED_SQL {
            vec![short_row.clone()]
        } else {
            Vec::new()
        };
        ready(Ok::<Vec<Row>, StoreError>(rows))
    };
    assert!(matches!(
        published_incidents(&mut no_count, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "update_count" })
    ));
    for (index, cell, column) in broken_columns {
        let mut row = good.clone();
        row.splice(index..=index, [cell]);
        let mut exec = |_scope: &TenantScope, statement: Statement| {
            let rows = if statement.sql == PUBLISHED_SQL { vec![row.clone()] } else { Vec::new() };
            ready(Ok::<Vec<Row>, StoreError>(rows))
        };
        let refused = published_incidents(&mut exec, &scope, &declared(), 1).await;
        assert!(matches!(refused, Err(StoreError::BadRow { column: name }) if name == column), "{column}");
    }
    let mut short = canned(vec![vec![int_cell(1)]]);
    assert!(matches!(
        published_incidents(&mut short, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "at" })
    ));
    Ok(())
}


fn stored(id: i64, started_at: i64, resolved: bool) -> StoredIncident {
    StoredIncident {
        tenant: TENANT_A.to_owned(),
        id,
        service: SERVICE.to_owned(),
        title: format!("incident-{id}"),
        published: true,
        started_at,
        resolved_at: resolved.then_some(started_at + 1),
        version: 0,
    }
}


const MORE_THAN_THE_LIMIT: i64 = 600;


const OLD_ONGOING: i64 = 4;


#[tokio::test]
async fn the_limit_never_cuts_an_ongoing_outage_before_a_resolved_incident_and_the_counts_are_exact() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    {
        let mut state = db.try_borrow_mut()?;
        state.incidents.extend((1..=OLD_ONGOING).map(|id| stored(id, id, false)));
        state
            .incidents
            .extend((OLD_ONGOING + 1..=MORE_THAN_THE_LIMIT).map(|id| stored(id, START + id, true)));
    }
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let read = read_published(&mut exec, &scope, &declared(), MAX_PUBLISHED).await?;
    assert_eq!(read.incidents.len(), usize::try_from(MAX_PUBLISHED)?);
    assert_eq!(
        read.incidents.iter().filter(|incident| incident.resolved_at.is_none()).count(),
        usize::try_from(OLD_ONGOING)?
    );
    assert_eq!(read.total, usize::try_from(MORE_THAN_THE_LIMIT)?);
    assert_eq!(read.ongoing, usize::try_from(OLD_ONGOING)?);
    let counts = db.try_borrow()?.log.iter().filter(|statement| statement.sql == COUNTS_SQL).count();
    assert_eq!(counts, 1);
    Ok(())
}


fn many_updates(db: &Rc<RefCell<Db>>, incident: i64, count: i64, message: &str) -> TestResult {
    let mut state = db.try_borrow_mut()?;
    state.updates.extend((0..count).map(|at| StoredUpdate {
        tenant: TENANT_A.to_owned(),
        incident,
        at,
        message: format!("{message}{at:03}"),
    }));
    Ok(())
}


const MANY_UPDATES: i64 = 30;


const PER_INCIDENT_CAP: usize = 20;


#[tokio::test]
async fn an_incident_reads_its_newest_updates_only_and_counts_the_others() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    db.try_borrow_mut()?.incidents.push(stored(1, START, false));
    many_updates(&db, 1, MANY_UPDATES, "m")?;
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let incidents = published_incidents(&mut exec, &scope, &declared(), MAX_PUBLISHED).await?;
    let only = incidents.first().ok_or("missing")?;
    assert_eq!(only.updates.len(), PER_INCIDENT_CAP);
    assert_eq!(only.omitted_updates, usize::try_from(MANY_UPDATES)? - PER_INCIDENT_CAP);
    assert_eq!(
        only.updates.first().map(|update| update.at),
        Some(MANY_UPDATES - i64::try_from(PER_INCIDENT_CAP)?)
    );
    assert_eq!(only.updates.last().map(|update| update.at), Some(MANY_UPDATES - 1));
    Ok(())
}


const BUDGET_INCIDENTS: i64 = 210;


#[tokio::test]
async fn the_message_bytes_of_a_read_are_budgeted_in_incident_order_and_the_cut_is_counted() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let message = "x".repeat(MAX_MESSAGE_CHARACTERS - THREE);
    (1..=BUDGET_INCIDENTS).try_for_each(|id| {
        db.try_borrow_mut()?.incidents.push(stored(id, START + id, true));
        many_updates(&db, id, MANY_UPDATES, &message)
    })?;
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let incidents = published_incidents(&mut exec, &scope, &declared(), MAX_PUBLISHED).await?;
    let bytes: usize = incidents
        .iter()
        .flat_map(|incident| incident.updates.iter())
        .map(|update| update.message.len())
        .sum();
    assert!(bytes <= usize::try_from(MAX_UPDATE_BYTES_PER_TICK)?);
    let first = incidents.first().ok_or("missing")?;
    let last = incidents.last().ok_or("missing")?;
    assert_eq!(first.updates.len(), PER_INCIDENT_CAP);
    assert_eq!(first.omitted_updates, usize::try_from(MANY_UPDATES)? - PER_INCIDENT_CAP);
    assert!(last.updates.is_empty());
    assert_eq!(last.omitted_updates, usize::try_from(MANY_UPDATES)?);
    Ok(())
}


#[test]
fn the_public_statements_bound_the_updates_per_incident_and_in_bytes_in_sql() -> TestResult {
    assert!(UPDATES_SQL.contains("LIMIT $3") && UPDATES_SQL.contains("running <= $4"));
    assert!(UPDATES_SQL.contains("ORDER BY at DESC, seq DESC"));
    assert_eq!(UPDATES_SQL.matches("tenant = $1").count(), TWO);
    assert_eq!(PUBLISHED_SQL.matches("tenant = $1").count(), TWO);
    Ok(())
}


#[test]
fn every_public_statement_filters_on_the_declared_services() -> TestResult {
    assert!(PUBLISHED_SQL.contains("tenant = $1 AND published AND service = ANY($3)"));
    assert!(UPDATES_SQL.contains("tenant = $1 AND published AND service = ANY($5)"));
    assert!(COUNTS_SQL.contains("tenant = $1 AND published AND service = ANY($2)"));
    Ok(())
}


fn on_service(id: i64, service: &str, started_at: i64) -> StoredIncident {
    StoredIncident {
        service: service.to_owned(),
        ..stored(id, started_at, false)
    }
}


const PRIVATE_INCIDENTS: i64 = 60;


#[tokio::test]
async fn an_undeclared_service_is_never_read_counted_or_allowed_to_spend_a_budget() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    {
        let mut state = db.try_borrow_mut()?;
        state.incidents.push(on_service(1, SERVICE, 0));
        state
            .incidents
            .extend((TWO_I64..=MORE_THAN_THE_LIMIT + 1).map(|id| on_service(id, PRIVATE, START + id)));
    }
    many_updates(&db, 1, MANY_UPDATES, "public")?;
    (TWO_I64..=PRIVATE_INCIDENTS).try_for_each(|id| many_updates(&db, id, MANY_UPDATES, &"x".repeat(MAX_MESSAGE_CHARACTERS - THREE)))?;
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let read = read_published(&mut exec, &scope, &declared(), MAX_PUBLISHED).await?;
    assert_eq!(read.incidents.len(), 1);
    assert_eq!((read.total, read.ongoing), (1, 1));
    let only = read.incidents.first().ok_or("missing")?;
    assert_eq!(only.service, SERVICE);
    assert_eq!(only.updates.len(), PER_INCIDENT_CAP);
    let both = vec![SERVICE.to_owned(), PRIVATE.to_owned()];
    let wide = read_published(&mut exec, &scope, &both, MAX_PUBLISHED).await?;
    assert_eq!(
        (wide.total, wide.incidents.len()),
        (usize::try_from(MORE_THAN_THE_LIMIT + 1)?, usize::try_from(MAX_PUBLISHED)?)
    );
    let none = read_published(&mut exec, &scope, &[], MAX_PUBLISHED).await?;
    assert_eq!((none.total, none.incidents.len()), (0, 0));
    Ok(())
}


#[tokio::test]
async fn declared_services_are_bounded_and_checked_before_any_statement() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    db.try_borrow_mut()?.incidents.push(stored(1, START, false));
    let mut exec = executor(&db);
    let scope = tenant_scope(TENANT_A)?;
    let many = vec![SERVICE.to_owned(); MAX_DECLARED_SERVICES + 1];
    assert!(matches!(
        read_published(&mut exec, &scope, &many, 1).await,
        Err(StoreError::TooManyServices {
            limit: MAX_DECLARED_SERVICES
        })
    ));
    let exact = vec![SERVICE.to_owned(); MAX_DECLARED_SERVICES];
    assert_eq!(read_published(&mut exec, &scope, &exact, 1).await?.incidents.len(), 1);
    let log_before = db.try_borrow()?.log.len();
    let bad_services = [
        vec!["a\nb".to_owned()],
        vec!["tab\there".to_owned()],
        vec!["a".repeat(DEFAULT_LIMITS.max_text_bytes + 1)],
    ];
    for services in bad_services {
        assert!(matches!(
            published_incidents(&mut exec, &scope, &services, 1).await,
            Err(StoreError::TextInvalid { .. } | StoreError::TextTooLong { .. })
        ));
    }
    assert_eq!(db.try_borrow()?.log.len(), log_before);
    Ok(())
}


#[tokio::test]
async fn the_counts_follow_the_tenant_scope() -> TestResult {
    let db = Rc::<RefCell<Db>>::default();
    let mut exec = executor(&db);
    let scope_a = tenant_scope(TENANT_A)?;
    let scope_b = tenant_scope(TENANT_B)?;
    create_incident(&mut exec, &scope_a, &new_incident("A one", true, START)).await?;
    create_incident(&mut exec, &scope_a, &new_incident("A hidden", false, START)).await?;
    create_incident(&mut exec, &scope_b, &new_incident("B one", true, START)).await?;
    create_incident(&mut exec, &scope_b, &new_incident("B two", true, START)).await?;
    let read = read_published(&mut exec, &scope_a, &declared(), MAX_PUBLISHED).await?;
    assert_eq!((read.incidents.len(), read.total, read.ongoing), (1, 1, 1));
    Ok(())
}


#[tokio::test]
async fn malformed_counts_are_refused_with_the_column_name() -> TestResult {
    let scope = tenant_scope(TENANT_A)?;
    let counted = |rows: Vec<Row>| {
        move |_scope: &TenantScope, statement: Statement| {
            let answer = if statement.sql == COUNTS_SQL { rows.clone() } else { Vec::new() };
            ready(Ok::<Vec<Row>, StoreError>(answer))
        }
    };
    let mut none = counted(Vec::new());
    assert!(matches!(
        read_published(&mut none, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "total" })
    ));
    let mut negative = counted(vec![vec![int_cell(-1), int_cell(0)]]);
    assert!(matches!(
        read_published(&mut negative, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "total" })
    ));
    let mut text = counted(vec![vec![int_cell(1), text_cell("x")]]);
    assert!(matches!(
        read_published(&mut text, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "ongoing" })
    ));
    let mut short = counted(vec![vec![int_cell(1)]]);
    assert!(matches!(
        read_published(&mut short, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "ongoing" })
    ));
    let mut failing = |_scope: &TenantScope, _statement: Statement| ready(Err::<Vec<Row>, StoreError>(bad("down")));
    assert!(matches!(
        read_published(&mut failing, &scope, &declared(), 1).await,
        Err(StoreError::BadRow { column: "down" })
    ));
    assert_eq!(count_of(&[vec![int_cell(TWO_I64)]], 0, "total")?, TWO);
    Ok(())
}
