use crate::common::{available, catalogue, entry, TestResult};
use software_catalog::installed::parse_installed;
use software_catalog::installed_rpm::parse_rpm_installed;
use software_catalog::installed_winget::parse_winget_export;
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Installed, InventoryIncomplete, Manager, Plan, Source};
use software_catalog::plan::{plan, MALFORMED_REASON};
use std::io::Cursor;


const SMALL: usize = 2;


const ENTRIES: usize = 3;


const WINGET_HEAD: &str = r#""SourceDetails":{"Name":"winget","Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe"}"#;


const UNATTRIBUTED_MANAGERS: usize = 4;


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


#[test]
fn winget_over_limit_plans_no_install_and_names_the_gap() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(SMALL + 1))), &small())?;
    let result = plan_for(winget, Manager::Winget, &installed)?;
    assert!(result.actions.is_empty());
    assert_eq!(
        result.inventory_incomplete,
        vec![InventoryIncomplete {
            manager: Manager::Winget,
            over_limit: SMALL + 1
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
    assert_eq!(apt_installed.over_limit, SMALL);
    assert_eq!(dnf_installed.over_limit, SMALL);
    assert!(no_install_or_update(&apt_plan));
    assert!(no_install_or_update(&dnf_plan));
    assert_eq!(
        apt_plan.inventory_incomplete,
        vec![InventoryIncomplete {
            manager: Manager::Apt,
            over_limit: SMALL
        }]
    );
    assert_eq!(
        dnf_plan.inventory_incomplete,
        vec![InventoryIncomplete {
            manager: Manager::Dnf,
            over_limit: SMALL
        }]
    );
    Ok(())
}


#[test]
fn one_malformed_package_makes_every_install_unknown_and_valid_rows_still_plan() -> TestResult {
    let text = winget_text(r#"{"PackageIdentifier":"A.One","Version":"1.0.0"},"junk",{"PackageIdentifier":"B.Two","Version":"2.0.0"}"#);
    let installed = parse_winget_export(Cursor::new(text), &Limits::default())?;
    assert_eq!(installed.malformed, 1);
    let result = plan_for(winget, Manager::Winget, &installed)?;
    let summary: Vec<(ActionKind, &str, Option<&str>)> = result
        .actions
        .iter()
        .map(|action| (action.kind, action.name.as_str(), action.reason))
        .collect();
    assert_eq!(
        summary,
        vec![(ActionKind::Update, "a", None), (ActionKind::Unknown, "c", Some(MALFORMED_REASON))]
    );
    assert!(result
        .actions
        .iter()
        .filter(|action| action.kind == ActionKind::Unknown)
        .all(|action| action.arguments.is_empty()));
    assert!(result.inventory_incomplete.is_empty());
    Ok(())
}


#[test]
fn a_gap_of_one_manager_leaves_other_managers_alone() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(SMALL + 1))), &small())?;
    let result = plan_for(apt, Manager::Apt, &installed)?;
    assert_eq!(result.actions.iter().filter(|action| action.kind == ActionKind::Install).count(), ENTRIES);
    Ok(())
}


#[test]
fn an_unattributed_gap_covers_every_manager() -> TestResult {
    let installed = Installed {
        over_limit: 1,
        ..Installed::default()
    };
    let result = plan_for(apt, Manager::Apt, &installed)?;
    assert!(result.actions.is_empty());
    assert_eq!(result.inventory_incomplete.len(), UNATTRIBUTED_MANAGERS);
    Ok(())
}


#[test]
fn no_gap_leaves_the_plan_unchanged() -> TestResult {
    let installed = parse_winget_export(Cursor::new(winget_text(&many(1))), &small())?;
    let result = plan_for(winget, Manager::Winget, &installed)?;
    assert_eq!(result.actions.iter().filter(|action| action.kind == ActionKind::Install).count(), ENTRIES);
    assert!(result.inventory_incomplete.is_empty());
    Ok(())
}
