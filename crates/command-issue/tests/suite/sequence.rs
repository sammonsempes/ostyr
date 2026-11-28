use crate::support::{capture, count_of, drain, locked, logged, rig, DEADLINE, SECOND, TENANT, THIRD};
use command_issue::error::IssueError;
use command_issue::limits::{MAX_AGENTS_PER_TENANT, MAX_UNCONFIRMED};
use command_issue::sequence::{
    allocate, check_agent_cap, check_gap, count_agents, lock_agent, lock_tenant, read_row, RowState, ALLOCATE_SQL, COUNT_SQL, LOCK_SQL, MIGRATIONS,
    MIGRATION_NAMESPACE, ROW_SQL, TENANT_LOCK_SQL,
};
use core_pg::migrate::check_embedded;
use core_pg::scope::tenant_scope;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};


const AGENT: &str = "agent1";


const TENANT_AGENTS: u64 = 4;


const FIVE_REFUSALS: usize = 5;


#[test]
fn the_gap_is_refused_beyond_the_unconfirmed_cap() -> Result<(), Box<dyn Error>> {
    assert!(check_gap(MAX_UNCONFIRMED - 1, 0, MAX_UNCONFIRMED).is_ok());
    assert!(matches!(check_gap(MAX_UNCONFIRMED, 0, MAX_UNCONFIRMED), Err(IssueError::SequenceGap)));
    assert!(check_gap(MAX_UNCONFIRMED + 1, SECOND, MAX_UNCONFIRMED).is_ok());
    assert!(check_gap(0, 1, MAX_UNCONFIRMED).is_ok());
    assert!(matches!(check_gap(u64::MAX, 0, MAX_UNCONFIRMED), Err(IssueError::SequenceGap)));
    Ok(())
}


#[test]
fn the_agent_cap_warns_on_the_first_refusal_and_each_power_of_two() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let refusals = AtomicU64::new(0);
    assert!(check_agent_cap(TENANT, MAX_AGENTS_PER_TENANT - 1, MAX_AGENTS_PER_TENANT, &refusals).is_ok());
    assert_eq!(refusals.load(Ordering::Relaxed), 0);
    let counts = (0..FIVE_REFUSALS)
        .map(|_| {
            let refused = check_agent_cap(TENANT, MAX_AGENTS_PER_TENANT, MAX_AGENTS_PER_TENANT, &refusals);
            assert!(matches!(refused, Err(IssueError::AgentLimit)));
            logged(&buffer).matches("tenant agent limit reached").count()
        })
        .collect::<Vec<usize>>();
    assert_eq!(
        counts,
        vec![
            1,
            usize::try_from(SECOND)?,
            usize::try_from(SECOND)?,
            usize::try_from(THIRD)?,
            usize::try_from(THIRD)?
        ]
    );
    assert!(logged(&buffer).contains(TENANT));
    Ok(())
}


#[test]
fn the_migration_is_embedded_and_valid() -> Result<(), Box<dyn Error>> {
    check_embedded(&MIGRATIONS)?;
    assert_eq!(MIGRATION_NAMESPACE, "command_issue");
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("PRIMARY KEY (tenant, agent_id, class)") && sql.contains("confirmed bigint NOT NULL DEFAULT 0"));
    Ok(())
}


#[test]
fn the_statements_pin_the_lock_text_the_class_and_the_greatest_allocation() -> Result<(), Box<dyn Error>> {
    assert!(LOCK_SQL.contains("hashtextextended('command-issue/' || $1::text || '@' || $2::text, 0::bigint)"));
    assert!(TENANT_LOCK_SQL.contains("hashtextextended('command-issue-tenant/' || $1::text, 0::bigint)"));
    assert!(ROW_SQL.contains("tenant = $1 AND agent_id = $2 AND class = 'routine'"));
    assert!(COUNT_SQL.contains("WHERE tenant = $1 AND class = 'routine'"));
    assert!(ALLOCATE_SQL.contains("last = GREATEST(agent_command_sequences.last, $3::bigint) + 1"));
    assert!(ALLOCATE_SQL.contains("VALUES ($1, $2, 'routine', $3::bigint + 1)"));
    Ok(())
}


#[tokio::test]
async fn every_statement_binds_the_tenant_first() -> Result<(), Box<dyn Error>> {
    let mut rig = rig().await?;
    rig.script.count.store(i64::try_from(TENANT_AGENTS)?, Ordering::SeqCst);
    *locked(&rig.script.row) = Some((1, 0));
    let scope = tenant_scope(TENANT)?;
    lock_agent(&rig.client, &scope, AGENT, DEADLINE).await?;
    lock_tenant(&rig.client, &scope, DEADLINE).await?;
    assert_eq!(
        read_row(&rig.client, &scope, AGENT, DEADLINE).await?,
        Some(RowState { last: 1, confirmed: 0 })
    );
    assert_eq!(count_agents(&rig.client, &scope, DEADLINE).await?, TENANT_AGENTS);
    assert_eq!(allocate(&rig.client, &scope, AGENT, 0, DEADLINE).await?, 1);
    let statements = drain(&mut rig.fake.statements);
    let bound = statements
        .iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .cloned()
        .collect::<Vec<String>>();
    assert_eq!(
        bound,
        vec![
            "PARAMS acme|agent1".to_owned(),
            "PARAMS acme".to_owned(),
            "PARAMS acme|agent1".to_owned(),
            "PARAMS acme".to_owned(),
            "PARAMS acme|agent1|0".to_owned()
        ]
    );
    assert_eq!(count_of(&statements, "GREATEST"), 1);
    Ok(())
}


#[tokio::test]
async fn an_absent_row_and_an_absent_count_read_as_nothing_and_zero() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let scope = tenant_scope(TENANT)?;
    assert_eq!(read_row(&rig.client, &scope, AGENT, DEADLINE).await?, None);
    locked(&rig.script.silent).push("count(*)");
    assert_eq!(count_agents(&rig.client, &scope, DEADLINE).await?, 0);
    Ok(())
}


#[tokio::test]
async fn numbers_out_of_range_are_refused() -> Result<(), Box<dyn Error>> {
    let rig = rig().await?;
    let scope = tenant_scope(TENANT)?;
    *locked(&rig.script.row) = Some((-1, 0));
    assert!(matches!(read_row(&rig.client, &scope, AGENT, DEADLINE).await, Err(IssueError::Range)));
    assert!(matches!(
        allocate(&rig.client, &scope, AGENT, u64::MAX, DEADLINE).await,
        Err(IssueError::Range)
    ));
    rig.script.counter.store(-FIVE_REFUSALS_I64, Ordering::SeqCst);
    assert!(matches!(allocate(&rig.client, &scope, AGENT, 0, DEADLINE).await, Err(IssueError::Range)));
    locked(&rig.script.silent).push("INSERT INTO agent_command_sequences");
    assert!(matches!(allocate(&rig.client, &scope, AGENT, 0, DEADLINE).await, Err(IssueError::Range)));
    Ok(())
}


const FIVE_REFUSALS_I64: i64 = 5;
