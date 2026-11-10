use chrono::{TimeZone, Utc};
use oncall::alert::{Cell, Phase};
use oncall::error::StoreError;
use oncall::rows::{decode_alert, parse_phase, phase_name, COL_LEVEL, COL_OPENED_AT, COL_STATE};
use oncall::types::Row;
use std::error::Error;


const COLUMNS: usize = 9;


const STAMP: i64 = 1_700_000_000;


fn good_row() -> Result<Row, Box<dyn Error>> {
    let stamp = Utc.timestamp_opt(STAMP, 0).single().ok_or("bad stamp")?;
    Ok(vec![
        Cell::Int(1),
        Cell::Text("fp".to_owned()),
        Cell::Text("escalated".to_owned()),
        Cell::Int(1),
        Cell::Int(1),
        Cell::Int(0),
        Cell::Time(Some(stamp)),
        Cell::Time(None),
        Cell::Time(None),
    ])
}


#[test]
fn a_good_row_decodes() -> Result<(), Box<dyn Error>> {
    let alert = decode_alert(&good_row()?)?;
    assert_eq!(alert.state.phase, Phase::Escalated);
    assert_eq!(alert.fingerprint, "fp");
    Ok(())
}


#[test]
fn every_column_of_the_wrong_type_is_refused() -> Result<(), Box<dyn Error>> {
    (0..COLUMNS).try_for_each(|index| {
        let mut row = good_row()?;
        row.splice(index..=index, [Cell::Bool(true)]);
        assert!(matches!(decode_alert(&row), Err(StoreError::BadRow { .. })), "column {index}");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_short_row_a_bad_state_a_negative_level_and_a_null_opened_at_are_refused() -> Result<(), Box<dyn Error>> {
    let short: Row = good_row()?.into_iter().take(COLUMNS - 1).collect();
    assert!(matches!(decode_alert(&short), Err(StoreError::BadRow { column: "resolved_at" })));
    let mut bad_state = good_row()?;
    bad_state.splice(COL_STATE..=COL_STATE, [Cell::Text("weird".to_owned())]);
    assert!(matches!(decode_alert(&bad_state), Err(StoreError::BadRow { column: "state" })));
    let mut negative = good_row()?;
    negative.splice(COL_LEVEL..=COL_LEVEL, [Cell::Int(-1)]);
    assert!(matches!(decode_alert(&negative), Err(StoreError::BadRow { column: "level" })));
    let mut no_open = good_row()?;
    no_open.splice(COL_OPENED_AT..=COL_OPENED_AT, [Cell::Time(None)]);
    assert!(matches!(decode_alert(&no_open), Err(StoreError::BadRow { column: "opened_at" })));
    Ok(())
}


#[test]
fn phase_names_round_trip() -> Result<(), Box<dyn Error>> {
    [Phase::Open, Phase::Acknowledged, Phase::Escalated, Phase::Resolved]
        .into_iter()
        .for_each(|phase| assert_eq!(parse_phase(phase_name(phase)), Some(phase)));
    Ok(())
}
