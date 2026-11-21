use crate::common::{available, catalogue, entry, gap, installed, TestResult};
use software_catalog::catalogue::check_entries;
use software_catalog::error::CatalogueError;
use software_catalog::installed::parse_installed;
use software_catalog::installed_rpm::parse_rpm_installed;
use software_catalog::installed_winget::{merge, parse_winget_export};
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Gap, Installed, InventoryGap, Manager, Plan, Source};
use software_catalog::plan::{plan, ABSENT_REASON, DUPLICATE_REASON, INCOMPLETE_REASON, MALFORMED_REASON};
use std::io::Cursor;


const ID_ARGUMENT: usize = 3;


const SMALL: usize = 2;


const ENTRIES: usize = 3;


const WINGET_HEAD: &str = r#""SourceDetails":{"Name":"winget","Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe"}"#;


fn small() -> Limits {
    Limits {
        max_installed: SMALL,
        ..Limits::default()
    }
}


fn winget_text(packages: &str) -> String {
    format!(r#"{{"Sources":[{{"Packages":[{packages}],{WINGET_HEAD}}}]}}"#)
}


fn everything() -> Assignment {
    Assignment {
        install: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        remove: vec![],
    }
}


fn plan_for(source: fn(&str) -> Source, manager: Manager, installed: &Installed) -> Result<Plan, Box<dyn std::error::Error>> {
    let cat = catalogue(vec![
        entry("a", source("A.One"), "2.0.0"),
        entry("b", source("B.Two"), "2.0.0"),
        entry("c", source("C.Three"), "2.0.0"),
    ]);
    Ok(plan(
        &cat,
        &everything(),
        installed,
        &available(manager, &["a.one", "b.two", "c.three", "A.One", "B.Two", "C.Three"]),
    )?)
}


fn winget(name: &str) -> Source {
    Source::Winget(name.to_string())
}


fn apt(name: &str) -> Source {
    Source::Apt(name.to_lowercase())
}


fn dnf(name: &str) -> Source {
    Source::Dnf(name.to_lowercase())
}


fn many(count: usize) -> String {
    (0..count)
        .map(|i| format!(r#"{{"PackageIdentifier":"P.N{i}","Version":"1.0.0"}}"#))
        .collect::<Vec<String>>()
        .join(",")
}


fn no_install_or_update(result: &Plan) -> bool {
    result
        .actions
        .iter()
        .all(|action| action.kind != ActionKind::Install && action.kind != ActionKind::Update)
}


fn summary(result: &Plan) -> Vec<(ActionKind, &str, Option<&str>)> {
    result
        .actions
        .iter()
        .filter(|action| action.kind != ActionKind::NotInCatalogue)
        .map(|action| (action.kind, action.name.as_str(), action.reason))
        .collect()
}


fn unknowns(reason: &'static str) -> Vec<(ActionKind, &'static str, Option<&'static str>)> {
    ["a", "b", "c"]
        .into_iter()
        .map(|name| (ActionKind::Unknown, name, Some(reason)))
        .collect()
}


#[test]
fn winget_over_limit_plans_no_install_and_names_the_gap() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(SMALL + 1))), &small())?;
    let result = plan_for(winget, Manager::Winget, &installed)?;
    assert_eq!(summary(&result), unknowns(INCOMPLETE_REASON));
    assert!(result.actions.iter().all(|action| action.arguments.is_empty()));
    assert_eq!(
        result.inventory_gaps,
        vec![InventoryGap {
            manager: Manager::Winget,
            over_limit: SMALL + 1,
            malformed: 0,
            duplicate_ids: 0
        }]
    );
    Ok(())
}


#[test]
fn apt_and_dnf_over_limit_plan_no_install_or_update() -> TestResult {
    let dpkg = "a.one\t1.0\tii\nb.two\t1.0\tii\nc.three\t1.0\tii\nd\t1.0\tii\n";
    let rpm = "a.one\t0:1.0-1\tx86_64\nb.two\t0:1.0-1\tx86_64\nc.three\t0:1.0-1\tx86_64\nd\t0:1.0-1\tx86_64\n";
    let apt_installed = parse_installed(Cursor::new(dpkg), &small())?;
    let dnf_installed = parse_rpm_installed(Cursor::new(rpm), &small())?;
    let apt_plan = plan_for(apt, Manager::Apt, &apt_installed)?;
    let dnf_plan = plan_for(dnf, Manager::Dnf, &dnf_installed)?;
    assert_eq!(gap(&apt_installed).over_limit, SMALL);
    assert_eq!(gap(&dnf_installed).over_limit, SMALL);
    assert!(no_install_or_update(&apt_plan));
    assert!(no_install_or_update(&dnf_plan));
    assert_eq!(summary(&apt_plan), unknowns(INCOMPLETE_REASON));
    assert_eq!(summary(&dnf_plan), unknowns(INCOMPLETE_REASON));
    assert_eq!(apt_plan.inventory_gaps.len(), 1);
    assert_eq!(dnf_plan.inventory_gaps.len(), 1);
    Ok(())
}


#[test]
fn a_gap_never_lets_an_uninstall_through() -> TestResult {
    let mut removal = entry("a", apt("libc6"), "2.0.0");
    removal.uninstall = true;
    let cat = catalogue(vec![removal]);
    let assignment = Assignment {
        install: vec![],
        remove: vec!["a".to_string()],
    };
    let held = parse_installed(Cursor::new("libc6\t1.0\thi\nd\t1.0\tii\ne\t1.0\tii\n"), &small())?;
    let held_plan = plan(&cat, &assignment, &held, &available(Manager::Apt, &[]))?;
    assert_eq!(gap(&held).over_limit, 1);
    assert_eq!(summary(&held_plan), vec![(ActionKind::Held, "a", None)]);
    let plain = parse_installed(Cursor::new("libc6\t1.0\tii\nd\t1.0\tii\ne\t1.0\tii\n"), &small())?;
    let second = plan(&cat, &assignment, &plain, &available(Manager::Apt, &[]))?;
    assert_eq!(summary(&second), vec![(ActionKind::Unknown, "a", Some(INCOMPLETE_REASON))]);
    Ok(())
}


#[test]
fn one_malformed_package_makes_every_action_unknown() -> TestResult {
    let text = winget_text(r#"{"PackageIdentifier":"A.One","Version":"1.0.0"},"junk",{"PackageIdentifier":"B.Two","Version":"2.0.0"}"#);
    let installed = parse_winget_export(Cursor::new(text), &Limits::default())?;
    assert_eq!(gap(&installed).malformed, 1);
    let result = plan_for(winget, Manager::Winget, &installed)?;
    assert_eq!(
        summary(&result),
        vec![
            (ActionKind::Unknown, "a", Some(MALFORMED_REASON)),
            (ActionKind::Unknown, "c", Some(MALFORMED_REASON))
        ]
    );
    assert!(result.actions.iter().all(|action| action.arguments.is_empty()));
    assert_eq!(
        result.inventory_gaps,
        vec![InventoryGap {
            manager: Manager::Winget,
            over_limit: 0,
            malformed: 1,
            duplicate_ids: 0
        }]
    );
    Ok(())
}


#[test]
fn a_winget_only_inventory_makes_other_managers_absent() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(1))), &small())?;
    let result = plan_for(apt, Manager::Apt, &installed)?;
    assert_eq!(summary(&result), unknowns(ABSENT_REASON));
    assert!(result.inventory_gaps.is_empty());
    Ok(())
}


#[test]
fn an_absent_manager_uninstall_is_unknown_and_a_plain_removal_is_nothing() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(1))), &small())?;
    let mut removal = entry("a", apt("pkg"), "2.0.0");
    removal.uninstall = true;
    let plain = entry("b", apt("other"), "2.0.0");
    let cat = catalogue(vec![removal, plain]);
    let assignment = Assignment {
        install: vec![],
        remove: vec!["a".to_string(), "b".to_string()],
    };
    let result = plan(&cat, &assignment, &installed, &available(Manager::Apt, &[]))?;
    assert_eq!(summary(&result), vec![(ActionKind::Unknown, "a", Some(ABSENT_REASON))]);
    let covered = plan(&cat, &assignment, &crate::common::installed(vec![]), &available(Manager::Apt, &[]))?;
    assert!(covered.actions.is_empty());
    Ok(())
}


fn managers_of(installed: &Installed) -> Vec<Manager> {
    installed.read_managers.iter().copied().collect()
}


fn gap_entry(manager: Manager, over_limit: usize, malformed: usize, duplicate_ids: usize) -> InventoryGap {
    InventoryGap {
        manager,
        over_limit,
        malformed,
        duplicate_ids,
    }
}


fn removal_plan(source: fn(&str) -> Source, manager: Manager, installed: &Installed, package: &str) -> Result<Plan, Box<dyn std::error::Error>> {
    let mut removal = entry("a", source(package), "2.0.0");
    removal.uninstall = true;
    let assignment = Assignment {
        install: vec![],
        remove: vec!["a".to_string()],
    };
    Ok(plan(&catalogue(vec![removal]), &assignment, installed, &available(manager, &[]))?)
}


#[test]
fn a_merged_mixed_inventory_charges_each_gap_to_its_own_manager() -> TestResult {
    let apt_ok = parse_installed(Cursor::new("a.one\t1.0\tii\n"), &Limits::default())?;
    let win_over = parse_winget_export(Cursor::new(winget_text(&many(SMALL + 1))), &small())?;
    let apt_bad = parse_installed(Cursor::new("a.one\t1.0\tii\nbroken line\n"), &Limits::default())?;
    let win_ok = parse_winget_export(Cursor::new(winget_text(&many(1))), &Limits::default())?;
    let first = merge(apt_ok, win_over);
    let second = merge(win_ok, apt_bad);
    assert_eq!(managers_of(&first), vec![Manager::Apt, Manager::Winget]);
    assert_eq!(managers_of(&second), vec![Manager::Apt, Manager::Winget]);
    let first_apt = plan_for(apt, Manager::Apt, &first)?;
    let first_win = plan_for(winget, Manager::Winget, &first)?;
    assert_eq!(
        summary(&first_apt),
        vec![
            (ActionKind::Install, "b", None),
            (ActionKind::Install, "c", None),
            (ActionKind::Update, "a", None)
        ]
    );
    assert_eq!(summary(&first_win), unknowns(INCOMPLETE_REASON));
    assert_eq!(first_apt.inventory_gaps, vec![gap_entry(Manager::Winget, SMALL + 1, 0, 0)]);
    let second_apt = plan_for(apt, Manager::Apt, &second)?;
    let second_win = plan_for(winget, Manager::Winget, &second)?;
    assert_eq!(summary(&second_apt), unknowns(MALFORMED_REASON));
    assert_eq!(
        summary(&second_win),
        vec![
            (ActionKind::Install, "a", None),
            (ActionKind::Install, "b", None),
            (ActionKind::Install, "c", None)
        ]
    );
    assert_eq!(second_win.inventory_gaps, vec![gap_entry(Manager::Apt, 0, 1, 0)]);
    Ok(())
}


#[test]
fn a_merge_never_covers_a_manager_no_reader_read() -> TestResult {
    let apt_ok = parse_installed(Cursor::new("a.one\t1.0\tii\n"), &Limits::default())?;
    let win_ok = parse_winget_export(Cursor::new(winget_text(&many(1))), &Limits::default())?;
    let both = merge(apt_ok, win_ok);
    let cat = catalogue(vec![
        entry("a", Source::Msi("t.msi".to_string()), "2.0.0"),
        entry("b", Source::Dnf("jq".to_string()), "2.0-1"),
    ]);
    let assignment = Assignment {
        install: vec!["a".to_string(), "b".to_string()],
        remove: vec![],
    };
    let result = plan(&cat, &assignment, &both, &available(Manager::Dnf, &["jq"]))?;
    assert_eq!(
        summary(&result),
        vec![
            (ActionKind::Unknown, "a", Some(ABSENT_REASON)),
            (ActionKind::Unknown, "b", Some(ABSENT_REASON))
        ]
    );
    Ok(())
}


#[test]
fn an_empty_inventory_covers_nothing() -> TestResult {
    let result = plan_for(apt, Manager::Apt, &Installed::default())?;
    assert_eq!(summary(&result), unknowns(ABSENT_REASON));
    assert!(result.inventory_gaps.is_empty());
    Ok(())
}


#[test]
fn a_lost_row_never_makes_a_removal_silent() -> TestResult {
    let lost_dup = parse_winget_export(
        Cursor::new(winget_text(
            r#"{"PackageIdentifier":"P.N0","PackageIdentifier":"P.N0","Version":"1.0.0"},{"PackageIdentifier":"P.N1"}"#,
        )),
        &Limits::default(),
    )?;
    let first = removal_plan(winget, Manager::Winget, &lost_dup, "P.N0")?;
    assert_eq!(summary(&first), vec![(ActionKind::Unknown, "a", Some(MALFORMED_REASON))]);
    assert_eq!(first.inventory_gaps, vec![gap_entry(Manager::Winget, 0, 1, 0)]);
    let lost_dpkg = parse_installed(Cursor::new("banned\nother\t1.0\tii\n"), &Limits::default())?;
    let second = removal_plan(apt, Manager::Apt, &lost_dpkg, "banned")?;
    assert_eq!(summary(&second), vec![(ActionKind::Unknown, "a", Some(MALFORMED_REASON))]);
    assert_eq!(second.inventory_gaps, vec![gap_entry(Manager::Apt, 0, 1, 0)]);
    let capped = parse_winget_export(Cursor::new(winget_text(&many(SMALL + 1))), &small())?;
    let third = removal_plan(winget, Manager::Winget, &capped, "P.N0")?;
    assert_eq!(summary(&third), vec![(ActionKind::Unknown, "a", Some(INCOMPLETE_REASON))]);
    assert_eq!(third.inventory_gaps, vec![gap_entry(Manager::Winget, SMALL + 1, 0, 0)]);
    Ok(())
}


#[test]
fn a_duplicate_id_removal_is_unknown_and_named() -> TestResult {
    let variant = parse_winget_export(
        Cursor::new(winget_text(
            r#"{"PackageIdentifier":"P.N0","Version":"1.0.0"},{"PackageIdentifier":"p.n0","Version":"1.0.0"}"#,
        )),
        &Limits::default(),
    )?;
    let first = removal_plan(winget, Manager::Winget, &variant, "P.N0")?;
    assert_eq!(summary(&first), vec![(ActionKind::Unknown, "a", Some(DUPLICATE_REASON))]);
    assert_eq!(first.inventory_gaps, vec![gap_entry(Manager::Winget, 0, 0, 1)]);
    let same = parse_winget_export(
        Cursor::new(winget_text(
            r#"{"PackageIdentifier":"P.N0","Version":"1.0.0"},{"PackageIdentifier":"P.N0","Version":"1.0.0"}"#,
        )),
        &Limits::default(),
    )?;
    let second = removal_plan(winget, Manager::Winget, &same, "P.N0")?;
    assert_eq!(summary(&second), vec![(ActionKind::Unknown, "a", Some(DUPLICATE_REASON))]);
    let other = removal_plan(winget, Manager::Winget, &variant, "P.Other")?;
    assert!(other.actions.iter().all(|action| action.kind == ActionKind::NotInCatalogue));
    Ok(())
}


#[test]
fn a_gap_keeps_ambiguous_and_names_it() -> TestResult {
    let multiarch = parse_installed(Cursor::new("libc6\t1.0\tii\nlibc6\t1.0\tii\nd\t1.0\tii\n"), &small())?;
    let result = removal_plan(apt, Manager::Apt, &multiarch, "libc6")?;
    assert_eq!(summary(&result), vec![(ActionKind::UninstallAmbiguous, "a", None)]);
    assert_eq!(result.inventory_gaps, vec![gap_entry(Manager::Apt, 1, 0, 0)]);
    Ok(())
}


#[test]
fn a_gap_of_an_unread_manager_is_not_named() -> TestResult {
    let mut built = installed(vec![]);
    built.read_managers.clear();
    built.gaps.insert(
        Manager::Winget,
        Gap {
            over_limit: 1,
            ..Gap::default()
        },
    );
    let result = plan_for(winget, Manager::Winget, &built)?;
    assert_eq!(summary(&result), unknowns(ABSENT_REASON));
    assert!(result.inventory_gaps.is_empty());
    Ok(())
}


#[test]
fn absent_is_named_even_when_the_package_is_not_offered() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(1))), &small())?;
    let cat = catalogue(vec![entry("a", apt("nano"), "2.0.0")]);
    let assignment = Assignment {
        install: vec!["a".to_string()],
        remove: vec![],
    };
    let result = plan(&cat, &assignment, &installed, &available(Manager::Apt, &[]))?;
    assert_eq!(summary(&result), vec![(ActionKind::Unknown, "a", Some(ABSENT_REASON))]);
    Ok(())
}


#[test]
fn merging_two_readers_of_one_manager_keeps_it_and_sums_gaps() -> TestResult {
    let left = parse_installed(Cursor::new("a\t1.0\tii\nbad\n"), &Limits::default())?;
    let right = parse_installed(Cursor::new("b\t1.0\tii\nbad\n"), &Limits::default())?;
    let merged = merge(left, right);
    assert_eq!(managers_of(&merged), vec![Manager::Apt]);
    assert_eq!(gap(&merged).malformed, SMALL);
    assert_eq!(merged.rows.len(), SMALL);
    Ok(())
}


#[test]
fn no_gap_leaves_the_plan_unchanged() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(1))), &small())?;
    let result = plan_for(winget, Manager::Winget, &installed)?;
    assert_eq!(result.actions.iter().filter(|action| action.kind == ActionKind::Install).count(), ENTRIES);
    assert!(result.inventory_gaps.is_empty());
    Ok(())
}


#[test]
fn winget_ids_differing_only_in_case_are_one_catalogue_source() -> TestResult {
    let twice = catalogue(vec![
        entry("banned", winget("Mozilla.Firefox"), "1.0.0"),
        entry("wanted", winget("mozilla.firefox"), "1.0.0"),
    ]);
    assert!(matches!(
        check_entries(&twice, &Limits::default()),
        Err(CatalogueError::DuplicateSource { name }) if name == "wanted"
    ));
    let apt_distinct = catalogue(vec![
        entry("a", Source::Apt("Foo".to_string()), "1.0"),
        entry("b", Source::Apt("foo".to_string()), "1.0"),
    ]);
    assert!(software_catalog::catalogue::check_sources(&apt_distinct).is_ok());
    Ok(())
}


#[test]
fn update_and_uninstall_carry_the_installed_spelling() -> TestResult {
    let inventory = parse_winget_export(
        Cursor::new(winget_text(r#"{"PackageIdentifier":"mozilla.firefox","Version":"1.0.0"}"#)),
        &Limits::default(),
    )?;
    let mut removal = entry("a", winget("Mozilla.Firefox"), "2.0.0");
    removal.uninstall = true;
    let cat = catalogue(vec![removal]);
    let names = |list: &[&str]| list.iter().map(|name| name.to_string()).collect::<Vec<String>>();
    let offer = available(Manager::Winget, &[]);
    let update = plan(
        &cat,
        &Assignment {
            install: names(&["a"]),
            remove: vec![],
        },
        &inventory,
        &offer,
    )?;
    let uninstall = plan(
        &cat,
        &Assignment {
            install: vec![],
            remove: names(&["a"]),
        },
        &inventory,
        &offer,
    )?;
    let spelled = "mozilla.firefox".to_string();
    let seen: Vec<(ActionKind, Option<&String>)> = update
        .actions
        .iter()
        .chain(uninstall.actions.iter())
        .map(|action| (action.kind, action.arguments.get(ID_ARGUMENT)))
        .collect();
    assert_eq!(seen, vec![(ActionKind::Update, Some(&spelled)), (ActionKind::Uninstall, Some(&spelled))]);
    let empty = parse_winget_export(Cursor::new(winget_text("")), &Limits::default())?;
    let fresh = plan(
        &cat,
        &Assignment {
            install: names(&["a"]),
            remove: vec![],
        },
        &empty,
        &offer,
    )?;
    let catalogue_spelling = "Mozilla.Firefox".to_string();
    assert_eq!(
        fresh.actions.iter().map(|action| action.arguments.get(ID_ARGUMENT)).collect::<Vec<_>>(),
        vec![Some(&catalogue_spelling)]
    );
    Ok(())
}
