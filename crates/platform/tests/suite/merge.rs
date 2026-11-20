use crate::fixture::{parts_of, unweighted_parts};
use crate::types::TestResult;
use core_api::model::{Requirement, Rule};
use core_api::routes::{core_access, route_key};
use core_api::types::AccessTable;
use platform::error::PlatformError;
use platform::merge::{merge_access, migration_plan, module_access};
use platform::model::Module;


const ALL: [Module; 8] = [
    Module::Alerts,
    Module::Cases,
    Module::Cmdb,
    Module::Risk,
    Module::Hunts,
    Module::Certificates,
    Module::Oncall,
    Module::Dhcp,
];


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
fn every_module_has_a_disjoint_table() -> TestResult {
    let merged = merge_access(ALL.iter().map(|module| module_access(*module)).collect())?;
    assert_eq!(merged.len(), ALL.iter().map(|module| module_access(*module).len()).sum::<usize>());
    let risk_key = module_access(Module::Risk).into_keys().next().ok_or("no risk route")?;
    let doubled = merge_access(vec![module_access(Module::Risk), module_access(Module::Risk)]);
    assert_eq!(doubled, Err(PlatformError::DuplicateRoute(risk_key)));
    for module in [Module::Hunts, Module::Certificates, Module::Oncall, Module::Dhcp] {
        let key = module_access(module).into_keys().min().ok_or("no route")?;
        assert_eq!(
            merge_access(vec![module_access(module), module_access(module)]),
            Err(PlatformError::DuplicateRoute(key))
        );
    }
    Ok(())
}


#[test]
fn migrations_run_in_dependency_order() -> TestResult {
    let names = |modules: &[Module]| migration_plan(modules).iter().map(|(namespace, _)| *namespace).collect::<Vec<_>>();
    assert_eq!(names(&[Module::Cmdb, Module::Cases, Module::Alerts]), ["alerts", "cases", "cmdb"]);
    assert_eq!(names(&[Module::Cases]), ["alerts", "cases"]);
    assert_eq!(names(&[Module::Alerts]), ["alerts"]);
    assert_eq!(names(&[Module::Cmdb]), ["cmdb"]);
    assert_eq!(names(&[Module::Risk]), ["alerts"]);
    assert_eq!(names(&[Module::Risk, Module::Alerts]), ["alerts"]);
    assert_eq!(names(&[Module::Alerts, Module::Risk]), ["alerts"]);
    assert_eq!(names(&[Module::Risk, Module::Cmdb]), ["alerts", "cmdb"]);
    assert_eq!(names(&[Module::Hunts]), ["hunt_packs"]);
    assert_eq!(names(&[Module::Certificates]), ["cert_inventory"]);
    assert_eq!(names(&[Module::Oncall]), ["oncall"]);
    assert_eq!(names(&[Module::Dhcp]), ["dhcp_kea"]);
    assert_eq!(names(&[Module::Dhcp, Module::Alerts]), ["alerts", "dhcp_kea"]);
    assert_eq!(
        names(&[Module::Oncall, Module::Hunts, Module::Certificates]),
        ["hunt_packs", "cert_inventory", "oncall"]
    );
    assert_eq!(
        names(&[Module::Oncall, Module::Cases, Module::Cmdb]),
        ["alerts", "cases", "cmdb", "oncall"]
    );
    assert_eq!(names(&[Module::Hunts, Module::Risk, Module::Alerts]), ["alerts", "hunt_packs"]);
    assert_eq!(
        names(&ALL),
        ["alerts", "cases", "cmdb", "hunt_packs", "cert_inventory", "oncall", "dhcp_kea"]
    );
    assert!(ALL.iter().all(|module| !migration_plan(&[*module]).is_empty()));
    assert!(migration_plan(&[Module::Cases])
        .iter()
        .all(|(_namespace, migrations)| !migrations.is_empty()));
    Ok(())
}


#[test]
fn module_parts_access_is_the_union_of_each_selected_module_table() -> TestResult {
    let (_dir, (_router, access, _documents)) = parts_of("alerts,cases,cmdb,risk,hunts,certificates,oncall,dhcp")?;
    let expected: Vec<String> = ALL.iter().flat_map(|module| module_access(*module).into_keys()).collect();
    assert_eq!(access.len(), expected.len());
    assert!(expected.iter().all(|key| access.contains_key(key)));
    let (_cases_dir, (_cases_router, cases_access, _cases_documents)) = parts_of("cases")?;
    assert_eq!(cases_access, module_access(Module::Cases));
    Ok(())
}


#[test]
fn module_parts_refuses_risk_without_a_weights_engine() -> TestResult {
    let error = unweighted_parts("alerts,risk")?.err().ok_or("built")?;
    assert_eq!(error, PlatformError::MissingWeightsFile);
    assert!(unweighted_parts("alerts,cases")?.is_ok());
    Ok(())
}
