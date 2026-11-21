use crate::common::{available, catalogue, entry, installed, TestResult};
use software_catalog::installed_winget::parse_winget_export;
use software_catalog::limits::Limits;
use software_catalog::model::{ActionKind, Assignment, Installed, InstalledRow, Manager, Plan, Source};
use software_catalog::plan::{plan, DUPLICATE_REASON};
use std::io::Cursor;


const HEAD: &str = r#""SourceDetails":{"Name":"winget","Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe"}"#;


fn export(ids: &[&str]) -> String {
    let packages: Vec<String> = ids
        .iter()
        .map(|id| format!(r#"{{"PackageIdentifier":"{id}","Version":"1.0.0"}}"#))
        .collect();
    format!(r#"{{"Sources":[{{"Packages":[{}],{HEAD}}}]}}"#, packages.join(","))
}


fn read(ids: &[&str]) -> Result<Installed, Box<dyn std::error::Error>> {
    Ok(parse_winget_export(Cursor::new(export(ids)), &Limits::default())?)
}


fn run(source: Source, uninstall: bool, installed: &Installed, manager: Manager) -> Result<Plan, Box<dyn std::error::Error>> {
    let mut wanted = entry("a", source, "1.0.0");
    wanted.uninstall = uninstall;
    let assignment = if uninstall {
        Assignment {
            install: vec![],
            remove: vec!["a".to_string()],
        }
    } else {
        Assignment {
            install: vec!["a".to_string()],
            remove: vec![],
        }
    };
    Ok(plan(
        &catalogue(vec![wanted]),
        &assignment,
        installed,
        &available(manager, &["Foo", "foo"]),
    )?)
}


fn kinds(result: &Plan) -> Vec<(ActionKind, Option<&str>)> {
    result.actions.iter().map(|action| (action.kind, action.reason)).collect()
}


#[test]
fn case_variant_winget_duplicates_are_unknown_for_remove_and_install() -> TestResult {
    let both = read(&["mozilla.firefox", "MOZILLA.FIREFOX"])?;
    let removal = run(Source::Winget("Mozilla.Firefox".to_string()), true, &both, Manager::Winget)?;
    assert_eq!(kinds(&removal), vec![(ActionKind::Unknown, Some(DUPLICATE_REASON))]);
    let install = run(Source::Winget("Mozilla.Firefox".to_string()), false, &both, Manager::Winget)?;
    assert_eq!(kinds(&install), vec![(ActionKind::Unknown, Some(DUPLICATE_REASON))]);
    Ok(())
}


#[test]
fn a_single_case_variant_row_is_the_catalogue_package() -> TestResult {
    let single = read(&["mozilla.firefox"])?;
    let removal = run(Source::Winget("Mozilla.Firefox".to_string()), true, &single, Manager::Winget)?;
    assert_eq!(kinds(&removal), vec![(ActionKind::Uninstall, None)]);
    let install = run(Source::Winget("Mozilla.Firefox".to_string()), false, &single, Manager::Winget)?;
    assert!(install.actions.is_empty());
    Ok(())
}


#[test]
fn apt_names_stay_case_sensitive() -> TestResult {
    let lower = installed(vec![InstalledRow {
        manager: Manager::Apt,
        package: "foo".to_string(),
        version: "1.0.0".to_string(),
        held: false,
    }]);
    let install = run(Source::Apt("Foo".to_string()), false, &lower, Manager::Apt)?;
    assert_eq!(kinds(&install), vec![(ActionKind::Install, None), (ActionKind::NotInCatalogue, None)]);
    Ok(())
}
