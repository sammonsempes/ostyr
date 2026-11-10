use chrono::{DateTime, TimeZone, Utc};
use core_pg::scope::{tenant_scope, TenantScope};
use oncall::alert::{Cell, Event, Outcome, Statement};
use oncall::error::StoreError;
use oncall::store::{apply_event, get_alert, open_alert, open_alerts, record_notification};
use oncall::types::Row;
use std::error::Error;
use std::future::ready;


const STAMP: i64 = 1_700_000_000;


fn at() -> Result<DateTime<Utc>, Box<dyn Error>> {
    Ok(Utc.timestamp_opt(STAMP, 0).single().ok_or("bad stamp")?)
}


#[tokio::test]
async fn an_executor_error_is_returned_by_every_operation() -> Result<(), Box<dyn Error>> {
    let scope = tenant_scope("acme")?;
    let mut failing = |_scope: &TenantScope, _statement: Statement| ready(Err::<Vec<Row>, StoreError>(StoreError::BadRow { column: "down" }));
    assert!(matches!(
        open_alert(&mut failing, &scope, "x", at()?).await,
        Err(StoreError::BadRow { column: "down" })
    ));
    assert!(matches!(get_alert(&mut failing, &scope, 1).await, Err(StoreError::BadRow { .. })));
    assert!(matches!(
        apply_event(&mut failing, &scope, 1, Event::Resolve, at()?).await,
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(
        record_notification(&mut failing, &scope, 1, "mail", &Outcome::Sent, at()?).await,
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(open_alerts(&mut failing, &scope, 1).await, Err(StoreError::BadRow { .. })));
    Ok(())
}


#[tokio::test]
async fn a_non_boolean_created_flag_is_refused() -> Result<(), Box<dyn Error>> {
    let scope = tenant_scope("acme")?;
    let stamp = at()?;
    let mut int_flag = |_scope: &TenantScope, _statement: Statement| {
        let row = vec![
            Cell::Int(1),
            Cell::Text("x".to_owned()),
            Cell::Text("open".to_owned()),
            Cell::Int(0),
            Cell::Int(1),
            Cell::Int(0),
            Cell::Time(Some(stamp)),
            Cell::Time(None),
            Cell::Time(None),
            Cell::Int(1),
        ];
        ready(Ok::<Vec<Row>, StoreError>(vec![row]))
    };
    assert!(matches!(
        open_alert(&mut int_flag, &scope, "x", stamp).await,
        Err(StoreError::BadRow { column: "created" })
    ));
    Ok(())
}
