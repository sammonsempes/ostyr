use crate::types::TestResult;
use core_api::model::{Requirement, Rule};
use core_api::routes::{core_access, route_key};
use core_api::types::AccessTable;
use platform::error::PlatformError;
use platform::merge::{merge_access, migration_plan, module_access};
use platform::model::Module;


const ALL: [Module; 3] = [Module::Alerts, Module::Cases, Module::Cmdb];


fn table(keys: &[&str], permission: &str) -> AccessTable {
    keys.iter()
        .map(|key| {
            (
                (*key).to_owned(),
                Rule {
                    requirement: Requirement::Permission(permission.to_owned()),
                    sensitive: false,
                },
            )
        })
        .collect()
}


#[test]
fn disjoint_tables_are_merged() -> TestResult {
    let merged = merge_access(vec![table(&["GET /a"], "a.read"), table(&["GET /b", "GET /c"], "b.read")])?;
    assert_eq!(merged.keys().map(String::as_str).collect::<Vec<_>>(), ["GET /a", "GET /b", "GET /c"]);
    assert_eq!(merge_access(Vec::new())?.len(), 0);
    Ok(())
}


#[test]
fn a_duplicate_is_refused_even_with_equal_rules_and_names_the_key() -> TestResult {
    let error = merge_access(vec![table(&["GET /a"], "a.read"), table(&["GET /a"], "a.read")])
        .err()
        .ok_or("merged")?;
    assert_eq!(error, PlatformError::DuplicateRoute("GET /a".to_owned()));
    assert!(error.to_string().contains("GET /a"));
    let other = merge_access(vec![table(&["GET /a"], "a.read"), table(&["GET /a"], "b.read")]);
    assert_eq!(other, Err(PlatformError::DuplicateRoute("GET /a".to_owned())));
    Ok(())
}


#[test]
fn a_core_key_is_refused() -> TestResult {
    let core_key = core_access().keys().next().ok_or("no core key")?.clone();
    let error = merge_access(vec![table(&["GET /a"], "a.read"), table(&[core_key.as_str()], "x.read")]);
    assert_eq!(error, Err(PlatformError::DuplicateRoute(core_key)));
    assert_eq!(
        merge_access(vec![table(&[route_key("GET", "/health").as_str()], "x.read")]),
        Err(PlatformError::DuplicateRoute("GET /health".to_owned()))
    );
    Ok(())
}


#[test]
fn the_three_modules_have_disjoint_tables() -> TestResult {
    let merged = merge_access(ALL.iter().map(|module| module_access(*module)).collect())?;
    assert_eq!(merged.len(), ALL.iter().map(|module| module_access(*module).len()).sum::<usize>());
    Ok(())
}


#[test]
fn migrations_run_in_dependency_order() -> TestResult {
    let names = |modules: &[Module]| migration_plan(modules).iter().map(|(namespace, _)| *namespace).collect::<Vec<_>>();
    assert_eq!(names(&[Module::Cmdb, Module::Cases, Module::Alerts]), ["alerts", "cases", "cmdb"]);
    assert_eq!(names(&[Module::Cases]), ["alerts", "cases"]);
    assert_eq!(names(&[Module::Alerts]), ["alerts"]);
    assert_eq!(names(&[Module::Cmdb]), ["cmdb"]);
    assert!(migration_plan(&[Module::Cases])
        .iter()
        .all(|(_namespace, migrations)| !migrations.is_empty()));
    Ok(())
}
