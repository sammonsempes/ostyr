use crate::common::{apt_entry, available, catalogue, entry, installed, row, TestResult};
use software_catalog::error::PlanError;
use software_catalog::limits::Limits;
use software_catalog::limits::MAX_ENTRIES;
use software_catalog::model::{ActionKind, Assignment, Available, Catalogue, Manager, Plan, Source};
use software_catalog::plan::{plan, plan_with};


const FOREIGN_POSITION: usize = 4;


const SMALL_NAMES: usize = 2;


fn offer(cat: &Catalogue) -> Available {
    Available {
        names: cat
            .entries
            .iter()
            .filter_map(|item| match &item.source {
                Source::Apt(package) => Some((Manager::Apt, package.clone())),
                Source::Dnf(package) => Some((Manager::Dnf, package.clone())),
                Source::Winget(_) | Source::Msi(_) => None,
            })
            .collect(),
        malformed: 0,
        over_limit: 0,
    }
}


fn names(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}


fn assignment(install: &[&str], remove: &[&str]) -> Assignment {
    Assignment {
        install: names(install),
        remove: names(remove),
    }
}


fn kinds(result: &Plan) -> Vec<(ActionKind, String)> {
    result.actions.iter().map(|action| (action.kind, action.name.clone())).collect()
}


#[test]
fn install_update_equal_downgrade_and_unknown() -> TestResult {
    let cat = catalogue(vec![
        apt_entry("new", "new", "1.0"),
        apt_entry("old", "old", "2.0"),
        apt_entry("same", "same", "1.0"),
        apt_entry("newer", "newer", "1.0"),
        apt_entry("odd", "odd", "1.0"),
    ]);
    let inv = installed(vec![
        row(Manager::Apt, "old", "1.0"),
        row(Manager::Apt, "same", "1.0"),
        row(Manager::Apt, "newer", "3.0"),
        row(Manager::Apt, "odd", "not~~a version!"),
        row(Manager::Apt, "extra", "9"),
    ]);
    let result = plan(&cat, &assignment(&["old", "new", "same", "newer", "odd", "old"], &[]), &inv, &offer(&cat))?;
    assert_eq!(
        kinds(&result),
        [
            (ActionKind::Install, "new".to_string()),
            (ActionKind::Update, "old".to_string()),
            (ActionKind::NewerThanCatalogue, "newer".to_string()),
            (ActionKind::Unknown, "odd".to_string()),
            (ActionKind::NotInCatalogue, "extra".to_string()),
        ]
    );
    let update = result.actions.get(1).ok_or("update")?;
    assert_eq!(update.installed_version.as_deref(), Some("1.0"));
    assert_eq!(update.target_version.as_deref(), Some("2.0"));
    assert_eq!(update.arguments, ["apt-get", "install", "-y", "--no-remove", "old=2.0"]);
    let foreign = result.actions.get(FOREIGN_POSITION).ok_or("foreign")?;
    assert!(foreign.arguments.is_empty() && foreign.target_version.is_none());
    Ok(())
}


#[test]
fn uninstall_only_what_the_catalogue_names_and_allows() -> TestResult {
    let mut allowed = apt_entry("nano", "nano", "1.0");
    allowed.uninstall = true;
    let cat = catalogue(vec![allowed, apt_entry("keep", "keep", "1.0"), apt_entry("absent", "absent", "1.0")]);
    let inv = installed(vec![
        row(Manager::Apt, "nano", "1.0"),
        row(Manager::Apt, "keep", "1.0"),
        row(Manager::Dnf, "absent", "1.0"),
    ]);
    let result = plan(&cat, &assignment(&[], &["nano", "keep", "absent"]), &inv, &offer(&cat))?;
    assert_eq!(
        kinds(&result),
        [
            (ActionKind::Uninstall, "nano".to_string()),
            (ActionKind::NotInCatalogue, "absent".to_string())
        ]
    );
    assert_eq!(result.refused_uninstalls, ["absent", "keep"]);
    let removal = result.actions.first().ok_or("removal")?;
    assert_eq!(removal.arguments, ["dpkg", "--remove", "nano"]);
    Ok(())
}


#[test]
fn a_forged_row_of_another_manager_is_never_removed_or_matched() -> TestResult {
    let mut nano = apt_entry("nano", "nano", "1.0");
    nano.uninstall = true;
    let cat = catalogue(vec![nano]);
    let inv = installed(vec![row(Manager::Winget, "nano", "1.0")]);
    let result = plan(&cat, &assignment(&["nano"], &["other"]).clone(), &inv, &offer(&cat));
    assert!(matches!(result, Err(PlanError::UnknownEntry { name }) if name == "other"));
    let removal = plan(&cat, &assignment(&[], &["nano"]), &inv, &offer(&cat))?;
    assert_eq!(kinds(&removal), [(ActionKind::NotInCatalogue, "nano".to_string())]);
    Ok(())
}


#[test]
fn winget_and_msi_rows_compare_by_semver_or_report_unknown() -> TestResult {
    let cat = catalogue(vec![
        entry("toys", Source::Winget("A.B".to_string()), "2.0.0"),
        entry("tool", Source::Msi("t.msi".to_string()), "release-x"),
    ]);
    let inv = installed(vec![row(Manager::Winget, "A.B", "1.0.0"), row(Manager::Msi, "t.msi", "release-y")]);
    let result = plan(&cat, &assignment(&["toys", "tool"], &[]), &inv, &offer(&cat))?;
    assert_eq!(
        kinds(&result),
        [(ActionKind::Update, "toys".to_string()), (ActionKind::Unknown, "tool".to_string())]
    );
    let equal = installed(vec![row(Manager::Msi, "t.msi", "release-x"), row(Manager::Winget, "A.B", "2.0.0")]);
    assert!(plan(&cat, &assignment(&["toys", "tool"], &[]), &equal, &offer(&cat))?.actions.is_empty());
    let padded = installed(vec![row(Manager::Winget, "A.B", "2.0.0+build")]);
    assert_eq!(
        kinds(&plan(&cat, &assignment(&["toys"], &[]), &padded, &offer(&cat))?),
        [(ActionKind::NewerThanCatalogue, "toys".to_string())]
    );
    Ok(())
}


#[test]
fn equal_versions_with_different_text_need_nothing() -> TestResult {
    let cat = catalogue(vec![apt_entry("jq", "jq", "1.0")]);
    let inv = installed(vec![row(Manager::Apt, "jq", "1.0-0")]);
    assert!(plan(&cat, &assignment(&["jq"], &[]), &inv, &offer(&cat))?.actions.is_empty());
    Ok(())
}


#[test]
fn assignment_errors_name_only_clean_entries() -> TestResult {
    let cat = catalogue(vec![apt_entry("jq", "jq", "1.0")]);
    let inv = installed(vec![]);
    assert!(matches!(
        plan(&cat, &assignment(&["ghost"], &[]), &inv, &offer(&cat)),
        Err(PlanError::UnknownEntry { name }) if name == "ghost"
    ));
    assert!(matches!(
        plan(&cat, &assignment(&["-bad\u{202e}"], &[]), &inv, &offer(&cat)),
        Err(PlanError::InvalidName)
    ));
    assert!(matches!(
        plan(&cat, &assignment(&["jq"], &["jq"]), &inv, &offer(&cat)),
        Err(PlanError::Conflict { name }) if name == "jq"
    ));
    let many = vec!["jq".to_string(); MAX_ENTRIES + 1];
    let flood = Assignment {
        install: many,
        remove: Vec::new(),
    };
    assert!(matches!(
        plan(&cat, &flood, &inv, &offer(&cat)),
        Err(PlanError::TooManyNames { limit: MAX_ENTRIES })
    ));
    let at_cap = Assignment {
        install: vec!["jq".to_string(); MAX_ENTRIES],
        remove: Vec::new(),
    };
    assert_eq!(plan(&cat, &at_cap, &inv, &offer(&cat))?.actions.len(), 1);
    let small = Limits {
        max_entries: SMALL_NAMES,
        ..Limits::default()
    };
    let names_at = |count: usize| Assignment {
        install: vec!["jq".to_string(); count],
        remove: Vec::new(),
    };
    assert!(plan_with(&cat, &names_at(SMALL_NAMES), &inv, &offer(&cat), &small).is_ok());
    assert!(matches!(
        plan_with(&cat, &names_at(SMALL_NAMES + 1), &inv, &offer(&cat), &small),
        Err(PlanError::TooManyNames { limit: SMALL_NAMES })
    ));
    let removals = Assignment {
        install: Vec::new(),
        remove: vec!["jq".to_string(); SMALL_NAMES + 1],
    };
    assert!(matches!(
        plan_with(&cat, &removals, &inv, &offer(&cat), &small),
        Err(PlanError::TooManyNames { .. })
    ));
    Ok(())
}


#[test]
fn a_package_the_manager_does_not_offer_is_unavailable_with_no_vector() -> TestResult {
    let cat = catalogue(vec![
        apt_entry("fuzzy", "libjq.", "1.0"),
        apt_entry("real", "tree", "1.0"),
        apt_entry("older", "older", "2.0"),
        entry("curl", Source::Dnf("curl".to_string()), "7.76-1.el9"),
    ]);
    let inv = installed(vec![row(Manager::Apt, "older", "1.0")]);
    let offered = available(Manager::Apt, &["tree", "libjq-dev"]);
    let result = plan(&cat, &assignment(&["fuzzy", "real", "older", "curl"], &[]), &inv, &offered)?;
    assert_eq!(
        kinds(&result),
        [
            (ActionKind::Install, "real".to_string()),
            (ActionKind::Unavailable, "curl".to_string()),
            (ActionKind::Unavailable, "fuzzy".to_string()),
            (ActionKind::Unavailable, "older".to_string()),
        ]
    );
    assert!(result
        .actions
        .iter()
        .filter(|action| action.kind == ActionKind::Unavailable)
        .all(|action| action.arguments.is_empty()));
    let dnf_offered = available(Manager::Dnf, &["curl"]);
    let dnf = plan(&cat, &assignment(&["curl"], &[]), &installed(vec![]), &dnf_offered)?;
    assert_eq!(
        dnf.actions.first().map(|action| action.arguments.clone()),
        Some(
            ["dnf", "install", "-y", "--setopt=obsoletes=False", "curl-0:7.76-1.el9"]
                .iter()
                .map(|item| item.to_string())
                .collect()
        )
    );
    Ok(())
}


#[test]
fn a_held_package_is_reported_held_not_updated() -> TestResult {
    let cat = catalogue(vec![apt_entry("nano", "nano", "2.0"), apt_entry("tree", "tree", "1.0")]);
    let mut held = row(Manager::Apt, "nano", "1.0");
    held.held = true;
    let mut held_equal = row(Manager::Apt, "tree", "1.0");
    held_equal.held = true;
    let result = plan(
        &cat,
        &assignment(&["nano", "tree"], &[]),
        &installed(vec![held, held_equal]),
        &offer(&cat),
    )?;
    assert_eq!(kinds(&result), [(ActionKind::Held, "nano".to_string())]);
    assert!(result.actions.iter().all(|action| action.arguments.is_empty()));
    Ok(())
}
