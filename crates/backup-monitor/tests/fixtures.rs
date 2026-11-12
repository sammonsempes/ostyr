use backup_monitor::compare::compare;
use backup_monitor::coverage::coverage;
use backup_monitor::declarations::load_declarations;
use backup_monitor::model::{CoverageStatus, FindingKind, Limits};
use backup_monitor::parse::{parse_borg, parse_restic};
use std::error::Error;
use time::macros::datetime;
use time::OffsetDateTime;


const DECLARATIONS: &str = include_str!("fixtures/declarations.yaml");


const RESTIC_PREVIOUS: &str = include_str!("fixtures/restic-previous.json");


const RESTIC_CURRENT: &str = include_str!("fixtures/restic-current.json");


const RESTIC_PRUNED: &str = include_str!("fixtures/restic-pruned.json");


const BORG_PREVIOUS: &str = include_str!("fixtures/borg-previous.json");


const BORG_CURRENT: &str = include_str!("fixtures/borg-current.json");


const BEFORE_COUNT: usize = 4;


const AFTER_DELETE_COUNT: usize = 3;


const AFTER_PRUNE_COUNT: usize = 2;


const FLOOR: usize = 3;


const NOW: OffsetDateTime = datetime!(2026-11-12 14:00 UTC);


#[test]
fn restic_capture_reports_one_deleted_snapshot() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "declarations.yaml")?;
    let previous = parse_restic(RESTIC_PREVIOUS.as_bytes(), "restic", &Limits::default())?;
    let current = parse_restic(RESTIC_CURRENT.as_bytes(), "restic", &Limits::default())?;
    assert_eq!((previous.snapshots.len(), current.snapshots.len()), (BEFORE_COUNT, AFTER_DELETE_COUNT));
    let findings = compare(&previous, &current, &declarations);
    assert_eq!(findings.len(), 1);
    assert!(matches!(&findings.first().ok_or("none")?.kind, FindingKind::Deleted { host, .. } if host.as_deref() == Some("web1")));
    let report = coverage(&[current], &declarations, NOW);
    assert_eq!(report.first().ok_or("none")?.status, CoverageStatus::Ok);
    assert_eq!(report.get(1).ok_or("none")?.status, CoverageStatus::Missing);
    Ok(())
}


#[test]
fn borg_capture_reports_one_deleted_archive() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "declarations.yaml")?;
    let previous = parse_borg(BORG_PREVIOUS.as_bytes(), declarations.hostname_from_name, &Limits::default())?;
    let current = parse_borg(BORG_CURRENT.as_bytes(), declarations.hostname_from_name, &Limits::default())?;
    assert_eq!((previous.snapshots.len(), current.snapshots.len()), (BEFORE_COUNT, AFTER_DELETE_COUNT));
    let findings = compare(&previous, &current, &declarations);
    assert_eq!(findings.len(), 1);
    assert!(matches!(&findings.first().ok_or("none")?.kind, FindingKind::Deleted { host, .. } if host.as_deref() == Some("web1")));
    Ok(())
}


#[test]
fn restic_capture_after_prune_is_below_the_floor() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "declarations.yaml")?;
    let current = parse_restic(RESTIC_CURRENT.as_bytes(), "restic", &Limits::default())?;
    let pruned = parse_restic(RESTIC_PRUNED.as_bytes(), "restic", &Limits::default())?;
    let findings = compare(&current, &pruned, &declarations);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings.first().ok_or("none")?.kind,
        FindingKind::RetentionBelowFloor {
            count: AFTER_PRUNE_COUNT,
            floor: FLOOR
        }
    );
    Ok(())
}
