#[path = "common/types.rs"]
mod types;


use core_config::plan::{action_name, drift, plan, rollback, ChangeKind};
use core_config::types::ConfigState;
use types::TestResult;


const UPDATE_INDEX: usize = 2;


const DELETE_INDEX: usize = 3;


fn state(items: &[(&str, &str)]) -> ConfigState {
    items.iter().map(|(key, text)| ((*key).to_owned(), (*text).to_owned())).collect()
}


#[test]
fn equal_states_give_an_empty_plan() -> TestResult {
    let current = state(&[("a", "1\n")]);
    assert!(plan(&current, &current).is_empty());
    Ok(())
}


#[test]
fn plan_orders_creates_updates_deletes_with_diffs() -> TestResult {
    let desired = state(&[("b", "new\n"), ("c", "same\n"), ("d", "two\n"), ("a", "x\n")]);
    let current = state(&[("c", "same\n"), ("d", "one\n"), ("z", "gone\n")]);
    let changes = plan(&desired, &current);
    let order: Vec<(ChangeKind, &str)> = changes.iter().map(|change| (change.kind, change.key.as_str())).collect();
    assert_eq!(
        order,
        vec![
            (ChangeKind::Create, "a"),
            (ChangeKind::Create, "b"),
            (ChangeKind::Update, "d"),
            (ChangeKind::Delete, "z")
        ]
    );
    let update = changes.get(UPDATE_INDEX).ok_or("no update")?;
    assert_eq!(update.before, "one\n");
    assert_eq!(update.after, "two\n");
    assert!(update.diff.contains("--- a/d") && update.diff.contains("+++ b/d"));
    assert!(update.diff.contains("-one") && update.diff.contains("+two"));
    let delete = changes.get(DELETE_INDEX).ok_or("no delete")?;
    assert!(delete.diff.contains("-gone"));
    let create = changes.first().ok_or("no create")?;
    assert!(create.diff.contains("+x"));
    Ok(())
}


#[test]
fn drift_and_rollback_are_plans() -> TestResult {
    let git = state(&[("a", "1\n")]);
    let real = state(&[("a", "edited\n")]);
    assert_eq!(drift(&git, &real), plan(&git, &real));
    assert_eq!(drift(&git, &real).len(), 1);
    assert!(drift(&git, &git).is_empty());
    let previous = state(&[("a", "0\n")]);
    assert_eq!(rollback(&previous, &git), plan(&previous, &git));
    Ok(())
}


#[test]
fn action_names() -> TestResult {
    assert_eq!(action_name(ChangeKind::Create), "config.create");
    assert_eq!(action_name(ChangeKind::Update), "config.update");
    assert_eq!(action_name(ChangeKind::Delete), "config.delete");
    Ok(())
}
