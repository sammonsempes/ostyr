use crate::common::{available, catalogue, entry, row, RemovalPlan, TestResult};
use software_catalog::installed_rpm::parse_rpm_installed;
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Installed, Manager, Source};
use software_catalog::plan::plan;
use std::io::Cursor;


const LAB_CAPTURE: &str = include_str!("../fixtures/lab-rpm-qa.txt");


fn assign(name: &str) -> Assignment {
    Assignment {
        install: vec![name.to_string()],
        remove: vec![],
    }
}


fn plan_kinds(rows: &[(&str, &str)], pin: &str) -> Result<Vec<ActionKind>, Box<dyn std::error::Error>> {
    let installed = Installed {
        rows: rows.iter().map(|(package, version)| row(Manager::Dnf, package, version)).collect(),
        ..Installed::default()
    };
    let cat = catalogue(vec![entry("pkg", Source::Dnf("pkg".to_string()), pin)]);
    let result = plan(&cat, &assign("pkg"), &installed, &available(Manager::Dnf, &["pkg"]))?;
    Ok(result.actions.iter().map(|action| action.kind).collect())
}


fn both_orders(
    first: (&'static str, &'static str),
    second: (&'static str, &'static str),
    pin: &str,
) -> Result<Vec<Vec<ActionKind>>, Box<dyn std::error::Error>> {
    Ok(vec![plan_kinds(&[first, second], pin)?, plan_kinds(&[second, first], pin)?])
}


#[test]
fn installonly_kernels_compare_the_highest_row_in_both_orders() -> TestResult {
    let old = ("pkg", "0:5.14.0-687.10.1.el9_8.0.1");
    let new = ("pkg", "0:5.14.0-687.66.1.el9_8");
    assert_eq!(both_orders(old, new, "5.14.0-687.66.1.el9_8")?, vec![vec![], vec![]]);
    assert_eq!(
        both_orders(old, new, "5.14.0-687.50.1.el9_8")?,
        vec![vec![ActionKind::NewerThanCatalogue], vec![ActionKind::NewerThanCatalogue]]
    );
    assert_eq!(
        both_orders(old, new, "5.14.0-700.1.1.el9_8")?,
        vec![vec![ActionKind::Update], vec![ActionKind::Update]]
    );
    Ok(())
}


#[test]
fn multilib_with_a_lagging_architecture_gives_the_same_action_in_both_orders() -> TestResult {
    let lagging = ("pkg", "0:2.34-1.el9");
    let current = ("pkg", "0:2.34-284.el9_8.4");
    assert_eq!(both_orders(lagging, current, "2.34-284.el9_8.4")?, vec![vec![], vec![]]);
    assert_eq!(
        both_orders(lagging, current, "2.35-1.el9")?,
        vec![vec![ActionKind::Update], vec![ActionKind::Update]]
    );
    Ok(())
}


#[test]
fn an_unparsable_row_among_several_makes_the_action_unknown_in_both_orders() -> TestResult {
    let good = ("pkg", "0:5.14.0-687.66.1.el9_8");
    let bad = ("pkg", "0:!!");
    let other_bad = ("pkg", "0:??");
    let unknown = vec![vec![ActionKind::Unknown], vec![ActionKind::Unknown]];
    assert_eq!(both_orders(good, bad, "5.14.0-687.66.1.el9_8")?, unknown);
    assert_eq!(both_orders(bad, other_bad, "1.0-1")?, unknown);
    Ok(())
}


#[test]
fn a_held_row_among_several_holds_the_update() -> TestResult {
    let mut held = row(Manager::Dnf, "pkg", "0:1.0-1");
    held.held = true;
    let installed = Installed {
        rows: vec![row(Manager::Dnf, "pkg", "0:1.1-1"), held],
        ..Installed::default()
    };
    let cat = catalogue(vec![entry("pkg", Source::Dnf("pkg".to_string()), "1.2-1")]);
    let result = plan(&cat, &assign("pkg"), &installed, &available(Manager::Dnf, &["pkg"]))?;
    assert_eq!(
        result.actions.iter().map(|action| action.kind).collect::<Vec<_>>(),
        vec![ActionKind::Held]
    );
    Ok(())
}


#[test]
fn the_fixture_kernels_plan_the_same_in_both_orders() -> TestResult {
    let installed = parse_rpm_installed(Cursor::new(LAB_CAPTURE.as_bytes()), &Limits::default())?;
    let mut reversed = installed.clone();
    reversed.rows.reverse();
    let offered = available(Manager::Dnf, &["kernel"]);
    let kinds_of = |source: &Installed, pin: &str| -> Result<Vec<ActionKind>, Box<dyn std::error::Error>> {
        let cat = catalogue(vec![entry("kernel", Source::Dnf("kernel".to_string()), pin)]);
        let result = plan(&cat, &assign("kernel"), source, &offered)?;
        Ok(result
            .actions
            .iter()
            .filter(|action| action.name == "kernel")
            .map(|action| action.kind)
            .collect())
    };
    let equal = "5.14.0-687.66.1.el9_8";
    let between = "5.14.0-687.50.1.el9_8";
    let above = "5.14.0-700.1.1.el9_8";
    assert_eq!(kinds_of(&installed, equal)?, kinds_of(&reversed, equal)?);
    assert_eq!(kinds_of(&installed, between)?, kinds_of(&reversed, between)?);
    assert_eq!(kinds_of(&installed, above)?, kinds_of(&reversed, above)?);
    assert!(kinds_of(&installed, equal)?.is_empty());
    assert_eq!(kinds_of(&installed, between)?, vec![ActionKind::NewerThanCatalogue]);
    assert_eq!(kinds_of(&installed, above)?, vec![ActionKind::Update]);
    Ok(())
}


fn removal(rows: &[(&str, &str)], held: bool) -> Result<RemovalPlan, Box<dyn std::error::Error>> {
    let installed = Installed {
        rows: rows
            .iter()
            .map(|(package, version)| {
                let mut found = row(Manager::Dnf, package, version);
                found.held = held;
                found
            })
            .collect(),
        ..Installed::default()
    };
    let mut removable = entry("pkg", Source::Dnf("pkg".to_string()), "1.0-1");
    removable.uninstall = true;
    let assignment = Assignment {
        install: vec![],
        remove: vec!["pkg".to_string()],
    };
    let result = plan(&catalogue(vec![removable]), &assignment, &installed, &available(Manager::Dnf, &["pkg"]))?;
    Ok(result
        .actions
        .iter()
        .filter(|action| action.name == "pkg")
        .map(|action| (action.kind, action.arguments.clone()))
        .collect())
}


#[test]
fn uninstall_of_a_package_with_several_rows_has_no_vector() -> TestResult {
    let two = [("pkg", "0:1.0-1"), ("pkg", "0:2.0-1")];
    assert_eq!(removal(&two, false)?, vec![(ActionKind::UninstallAmbiguous, Vec::<String>::new())]);
    assert_eq!(removal(&two, true)?, vec![(ActionKind::Held, Vec::<String>::new())]);
    let installed = parse_rpm_installed(Cursor::new(LAB_CAPTURE.as_bytes()), &Limits::default())?;
    let mut kernel = entry("kernel", Source::Dnf("kernel".to_string()), "5.14.0-687.66.1.el9_8");
    kernel.uninstall = true;
    let assignment = Assignment {
        install: vec![],
        remove: vec!["kernel".to_string()],
    };
    let result = plan(&catalogue(vec![kernel]), &assignment, &installed, &available(Manager::Dnf, &["kernel"]))?;
    let action = result.actions.iter().find(|found| found.name == "kernel").ok_or("kernel")?;
    assert_eq!(action.kind, ActionKind::UninstallAmbiguous);
    assert!(action.arguments.is_empty());
    Ok(())
}


#[test]
fn uninstall_of_a_single_row_package_keeps_the_erase_vector() -> TestResult {
    let erase = vec!["rpm".to_string(), "--erase".to_string(), "pkg".to_string()];
    assert_eq!(removal(&[("pkg", "0:1.0-1")], false)?, vec![(ActionKind::Uninstall, erase)]);
    Ok(())
}
