use backup_monitor::compare::compare;
use backup_monitor::coverage::coverage;
use backup_monitor::declarations::load_declarations;
use backup_monitor::model::{CoverageStatus, Declarations, FindingKind, Listing, Snapshot};
use core_pg::scope::tenant_of;
use std::error::Error;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};


const DECLARATIONS: &str = "tenant: acme\ncritical:\n  - host: web1\n    max_age_hours: 24\n  - host: db1\n    max_age_hours: 1\n\
                            repositories:\n  - repository: repo\n    expected_min_snapshots: 3\n";


const FIRST: u32 = 1;


const SECOND: u32 = 2;


const THIRD: u32 = 3;


const FOURTH: u32 = 4;


const FLOOR: usize = 3;


const TWO: usize = 2;


const HOURS_LIMIT: i64 = 24;


const SKEW_MINUTES: i64 = 5;


const ONE_SECOND: i64 = 1;


const DAY_9: OffsetDateTime = datetime!(2026-11-09 02:00 UTC);


const DAY_10: OffsetDateTime = datetime!(2026-11-10 02:00 UTC);


const DAY_11: OffsetDateTime = datetime!(2026-11-11 02:00 UTC);


const DAY_12: OffsetDateTime = datetime!(2026-11-12 02:00 UTC);


const NOW: OffsetDateTime = datetime!(2026-11-12 10:00 UTC);


const EARLY: OffsetDateTime = datetime!(2026-11-01 08:00 UTC);


const RECENT: OffsetDateTime = datetime!(2026-11-12 08:00 UTC);


const RECENTER: OffsetDateTime = datetime!(2026-11-12 09:30 UTC);


const RECENTEST: OffsetDateTime = datetime!(2026-11-12 09:59 UTC);


const END_OF_TIME: OffsetDateTime = datetime!(9999-12-31 23:59:59 UTC);


fn declarations() -> Result<Declarations, Box<dyn Error>> {
    Ok(load_declarations(DECLARATIONS, "d.yaml")?)
}


fn id_of(number: u32) -> String {
    format!("{number:064x}")
}


fn snapshot(number: u32, host: &str, time: OffsetDateTime) -> Snapshot {
    Snapshot {
        id: id_of(number),
        time,
        host: Some(host.to_owned()),
        paths: Vec::new(),
        tags: Vec::new(),
    }
}


fn listing(repository: &str, snapshots: Vec<Snapshot>) -> Listing {
    Listing {
        repository: repository.to_owned(),
        snapshots,
        skipped: Default::default(),
    }
}


fn four() -> Vec<Snapshot> {
    vec![
        snapshot(FIRST, "web1", DAY_9),
        snapshot(SECOND, "web1", DAY_10),
        snapshot(THIRD, "web1", DAY_11),
        snapshot(FOURTH, "web1", DAY_12),
    ]
}


fn without(snapshots: &[Snapshot], gone: &[u32]) -> Vec<Snapshot> {
    snapshots
        .iter()
        .filter(|item| !gone.iter().any(|number| item.id == id_of(*number)))
        .cloned()
        .collect()
}


#[test]
fn coverage_ok_stale_and_missing() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let listings = vec![listing("repo", four())];
    let report = coverage(&listings, &declarations, NOW);
    assert_eq!(report.len(), declarations.critical.len());
    let web = report.first().ok_or("no web")?;
    assert_eq!(tenant_of(&web.tenant), "acme");
    assert_eq!(web.host, "web1");
    assert_eq!(web.newest, Some(DAY_12));
    assert_eq!(web.status, CoverageStatus::Ok);
    let db = report.get(1).ok_or("no db")?;
    assert_eq!((db.newest, &db.status), (None, &CoverageStatus::Missing));
    assert_eq!(tenant_of(&db.tenant), "acme");
    Ok(())
}


#[test]
fn coverage_age_boundary() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let listings = vec![listing("repo", four())];
    let at_limit = coverage(&listings, &declarations, DAY_12 + Duration::hours(HOURS_LIMIT));
    assert_eq!(at_limit.first().ok_or("no web")?.status, CoverageStatus::Ok);
    let age = Duration::hours(HOURS_LIMIT) + Duration::seconds(ONE_SECOND);
    let over = coverage(&listings, &declarations, DAY_12 + age);
    assert_eq!(over.first().ok_or("no web")?.status, CoverageStatus::Stale { age });
    Ok(())
}


#[test]
fn coverage_takes_the_newest_across_listings_and_ignores_other_hosts() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let listings = vec![
        listing("repo", vec![snapshot(FIRST, "db1", RECENT), snapshot(SECOND, "web1", EARLY)]),
        listing("other", vec![snapshot(THIRD, "db1", RECENTER), snapshot(FOURTH, "mail", RECENTEST)]),
    ];
    let report = coverage(&listings, &declarations, NOW);
    let web = report.first().ok_or("no web")?;
    assert!(matches!(web.status, CoverageStatus::Stale { .. }));
    let db = report.get(1).ok_or("no db")?;
    assert_eq!((db.newest, &db.status), (Some(RECENTER), &CoverageStatus::Ok));
    Ok(())
}


#[test]
fn a_snapshot_with_no_host_covers_nobody() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let mut unknown = snapshot(FIRST, "web1", RECENT);
    unknown.host = None;
    let report = coverage(&[listing("repo", vec![unknown])], &declarations, NOW);
    assert_eq!(report.first().ok_or("no web")?.status, CoverageStatus::Missing);
    Ok(())
}


#[test]
fn a_forged_future_snapshot_proves_nothing() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let edge = NOW + Duration::minutes(SKEW_MINUTES);
    let near = snapshot(FIRST, "web1", edge);
    let far = snapshot(SECOND, "db1", edge + Duration::seconds(ONE_SECOND));
    let report = coverage(&[listing("repo", vec![near, far])], &declarations, NOW);
    let web = report.first().ok_or("no web")?;
    assert_eq!((web.newest, &web.status), (Some(edge), &CoverageStatus::Ok));
    assert_eq!(report.get(1).ok_or("no db")?.status, CoverageStatus::Missing);
    Ok(())
}


#[test]
fn coverage_survives_a_now_at_the_end_of_time() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let report = coverage(&[listing("repo", four())], &declarations, END_OF_TIME);
    assert!(matches!(report.first().ok_or("no web")?.status, CoverageStatus::Stale { .. }));
    Ok(())
}


#[test]
fn a_deleted_middle_snapshot_is_reported() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let previous = listing("repo", four());
    let current = listing("repo", without(&four(), &[SECOND]));
    let findings = compare(&previous, &current, &declarations);
    assert_eq!(findings.len(), 1);
    let finding = findings.first().ok_or("no finding")?;
    assert_eq!(tenant_of(&finding.tenant), "acme");
    assert_eq!(finding.repository, "repo");
    assert_eq!(
        finding.kind,
        FindingKind::Deleted {
            id: id_of(SECOND),
            time: DAY_10,
            host: Some("web1".to_owned())
        }
    );
    Ok(())
}


#[test]
fn a_pruned_oldest_snapshot_is_retention_not_a_finding() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let findings = compare(&listing("repo", four()), &listing("repo", without(&four(), &[FIRST])), &declarations);
    assert!(findings.is_empty());
    Ok(())
}


#[test]
fn hiding_a_deletion_behind_the_oldest_still_reports_the_middle_one() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let current = listing("repo", without(&four(), &[FIRST, THIRD]));
    let findings = compare(&listing("repo", four()), &current, &declarations);
    assert_eq!(findings.len(), TWO);
    assert!(matches!(&findings.first().ok_or("no finding")?.kind, FindingKind::Deleted { time, .. } if *time == DAY_11));
    assert_eq!(
        findings.get(1).ok_or("no floor")?.kind,
        FindingKind::RetentionBelowFloor { count: TWO, floor: FLOOR }
    );
    Ok(())
}


#[test]
fn the_newest_deleted_is_reported_and_an_emptied_host_reports_all() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let newest_gone = compare(&listing("repo", four()), &listing("repo", without(&four(), &[FOURTH])), &declarations);
    assert_eq!(newest_gone.len(), 1);
    let all_gone = compare(&listing("repo", four()), &listing("repo", Vec::new()), &declarations);
    let deleted = all_gone
        .iter()
        .filter(|finding| matches!(finding.kind, FindingKind::Deleted { .. }))
        .count();
    assert_eq!(deleted, four().len());
    Ok(())
}


#[test]
fn oldest_is_judged_per_host() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let previous = listing(
        "repo",
        vec![
            snapshot(FIRST, "web1", DAY_10),
            snapshot(SECOND, "web1", DAY_11),
            snapshot(THIRD, "db1", EARLY),
            snapshot(FOURTH, "db1", DAY_12),
        ],
    );
    let current = listing("repo", vec![snapshot(SECOND, "web1", DAY_11), snapshot(FOURTH, "db1", DAY_12)]);
    let findings = compare(&previous, &current, &declarations);
    assert!(findings.iter().all(|finding| !matches!(finding.kind, FindingKind::Deleted { .. })));
    Ok(())
}


#[test]
fn different_repositories_are_never_compared() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let current = listing("repo", vec![snapshot(FOURTH, "web1", DAY_12)]);
    let findings = compare(&listing("old", four()), &current, &declarations);
    assert_eq!(findings.len(), TWO);
    assert_eq!(
        findings.first().ok_or("none")?.kind,
        FindingKind::RepositoryChanged {
            previous: "old".to_owned(),
            current: "repo".to_owned()
        }
    );
    assert_eq!(
        findings.get(1).ok_or("none")?.kind,
        FindingKind::RetentionBelowFloor { count: 1, floor: FLOOR }
    );
    Ok(())
}


#[test]
fn retention_floor_at_n_and_n_minus_one() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let three = listing("repo", without(&four(), &[FIRST]));
    assert!(compare(&three, &three, &declarations).is_empty());
    let two = listing("repo", without(&four(), &[FIRST, SECOND]));
    let findings = compare(&three, &two, &declarations);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings.first().ok_or("none")?.kind,
        FindingKind::RetentionBelowFloor { count: TWO, floor: FLOOR }
    );
    let unlisted = listing("elsewhere", Vec::new());
    assert!(compare(&unlisted, &unlisted, &declarations).is_empty());
    Ok(())
}


#[test]
fn a_same_second_deletion_is_reported_by_id_order() -> Result<(), Box<dyn Error>> {
    let declarations = declarations()?;
    let both = listing("repo", vec![snapshot(FIRST, "web1", DAY_10), snapshot(SECOND, "web1", DAY_10)]);
    let keeps_first = listing("repo", vec![snapshot(FIRST, "web1", DAY_10)]);
    let keeps_second = listing("repo", vec![snapshot(SECOND, "web1", DAY_10)]);
    let reported = compare(&both, &keeps_first, &declarations);
    assert!(matches!(&reported.first().ok_or("no finding")?.kind, FindingKind::Deleted { id, .. } if *id == id_of(SECOND)));
    assert!(!compare(&both, &keeps_second, &declarations)
        .iter()
        .any(|finding| matches!(finding.kind, FindingKind::Deleted { .. })));
    Ok(())
}
