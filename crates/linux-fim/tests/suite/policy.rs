use crate::support::{fixture, role, BIG_COUNT, DEFAULT_TABLE, OVER_CAP, PREFIX_KPROBES, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::error::PolicyError;
use linux_fim::limits::{default_limits, MAX_SELECTOR_VALUES};
use linux_fim::model::{Limits, Role, TracingPolicy, WatchKind};
use linux_fim::policy::{
    build_policy, directory_of, render_policy, render_with, HOOK_FILE_TRUNCATE, HOOK_MKNOD, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION,
    MAY_WRITE_MASK,
};
use linux_fim::roles::load_roles;
use serde::ser::Error as SerError;
use serde_saphyr::SerializeError;
use std::fs;


fn named_role(name: &str) -> Result<Role, Box<dyn std::error::Error>> {
    let table = load_roles(&fs::read_to_string(DEFAULT_TABLE)?, &default_limits())?;
    table
        .roles
        .into_iter()
        .find(|candidate| candidate.name == name)
        .ok_or_else(|| "no such role".into())
}


fn failing(_policy: &TracingPolicy) -> Result<String, SerializeError> {
    Err(SerializeError::custom("refused"))
}


fn calls(role: &Role) -> Result<Vec<String>, PolicyError> {
    Ok(build_policy(role, &default_limits())?
        .spec
        .kprobes
        .into_iter()
        .map(|probe| probe.call)
        .collect())
}


#[test]
fn the_server_role_renders_the_golden_policy() -> TestResult {
    assert_eq!(render_policy(&named_role("server")?, &default_limits())?, fixture("server.policy.yaml")?);
    Ok(())
}


#[test]
fn the_workstation_role_renders_the_golden_policy() -> TestResult {
    assert_eq!(
        render_policy(&named_role("workstation")?, &default_limits())?,
        fixture("workstation.policy.yaml")?
    );
    Ok(())
}


#[test]
fn a_hostile_looking_path_is_data_in_the_document() -> TestResult {
    let text = render_policy(&role("a", &[("/etc/a: b", WatchKind::File)], &[]), &default_limits())?;
    assert!(text.contains("- '/etc/a: b'") || text.contains("- \"/etc/a: b\""), "{text}");
    Ok(())
}


#[test]
fn the_write_mask_selects_may_write_only() -> TestResult {
    let policy = build_policy(&named_role("server")?, &default_limits())?;
    let permission = policy
        .spec
        .kprobes
        .iter()
        .find(|probe| probe.call == HOOK_PERMISSION)
        .ok_or("no permission kprobe")?;
    assert!(permission.selectors.iter().all(|selector| selector
        .match_args
        .iter()
        .any(|arg| arg.operator == "Mask" && arg.values == [MAY_WRITE_MASK])));
    Ok(())
}


#[test]
fn only_files_give_permission_and_truncate_probes() -> TestResult {
    let only_files = role("a", &[("/etc/a", WatchKind::File)], &[]);
    assert_eq!(calls(&only_files)?, [HOOK_PERMISSION, HOOK_PATH_TRUNCATE, HOOK_FILE_TRUNCATE]);
    Ok(())
}


#[test]
fn prefixes_add_the_creation_probe_on_the_directory() -> TestResult {
    let only_prefix = role("a", &[("/etc/cron.d/", WatchKind::Prefix)], &[]);
    let policy = build_policy(&only_prefix, &default_limits())?;
    let mknod = policy
        .spec
        .kprobes
        .iter()
        .find(|probe| probe.call == HOOK_MKNOD)
        .ok_or("no mknod kprobe")?;
    let values: Vec<&String> = mknod
        .selectors
        .iter()
        .flat_map(|selector| selector.match_args.iter().flat_map(|arg| arg.values.iter()))
        .collect();
    assert_eq!(values, ["/etc/cron.d"]);
    assert_eq!(policy.spec.kprobes.len(), PREFIX_KPROBES);
    Ok(())
}


#[test]
fn honeytokens_alone_give_one_open_probe() -> TestResult {
    assert_eq!(calls(&role("a", &[], &["/srv/a"]))?, [HOOK_OPEN]);
    Ok(())
}


#[test]
fn the_policy_name_carries_the_role() -> TestResult {
    assert_eq!(
        build_policy(&role("web-1", &[], &["/srv/a"]), &default_limits())?.metadata.name,
        "ostyr-fim-web-1"
    );
    Ok(())
}


#[test]
fn a_role_with_nothing_is_refused() -> TestResult {
    assert!(matches!(render_policy(&role("a", &[], &[]), &default_limits()), Err(PolicyError::Empty)));
    Ok(())
}


fn paths(prefix: &str, suffix: &str, count: usize) -> Vec<String> {
    (0..count).map(|index| format!("{prefix}{index}{suffix}")).collect()
}


#[test]
fn more_values_than_one_selector_takes_are_refused_never_split() -> TestResult {
    let limits = Limits {
        max_selector_values: SMALL_CAP,
        ..default_limits()
    };
    let many_files: Vec<String> = paths("/etc/f", "", SMALL_CAP + 1);
    let many_prefixes: Vec<String> = paths("/etc/p", "/", SMALL_CAP + 1);
    let many_tokens: Vec<String> = paths("/srv/t", "", SMALL_CAP + 1);
    let files: Vec<(&str, WatchKind)> = many_files.iter().map(|path| (path.as_str(), WatchKind::File)).collect();
    let prefixes: Vec<(&str, WatchKind)> = many_prefixes.iter().map(|path| (path.as_str(), WatchKind::Prefix)).collect();
    let tokens: Vec<&str> = many_tokens.iter().map(String::as_str).collect();
    assert!(matches!(
        render_policy(&role("a", &files, &[]), &limits),
        Err(PolicyError::TooManyFiles {
            count: OVER_CAP,
            max: SMALL_CAP
        })
    ));
    assert!(matches!(
        render_policy(&role("a", &prefixes, &[]), &limits),
        Err(PolicyError::TooManyPrefixes {
            count: OVER_CAP,
            max: SMALL_CAP
        })
    ));
    assert!(matches!(
        render_policy(&role("a", &[], &tokens), &limits),
        Err(PolicyError::TooManyHoneytokens {
            count: OVER_CAP,
            max: SMALL_CAP
        })
    ));
    Ok(())
}


#[test]
fn the_default_cap_is_what_tetragon_documents() -> TestResult {
    let at_cap = paths("/etc/f", "", MAX_SELECTOR_VALUES);
    let over_cap = paths("/etc/f", "", BIG_COUNT);
    let accepted: Vec<(&str, WatchKind)> = at_cap.iter().map(|path| (path.as_str(), WatchKind::File)).collect();
    let refused: Vec<(&str, WatchKind)> = over_cap.iter().map(|path| (path.as_str(), WatchKind::File)).collect();
    render_policy(&role("a", &accepted, &[]), &default_limits())?;
    assert!(render_policy(&role("a", &refused, &[]), &default_limits()).is_err());
    Ok(())
}


#[test]
fn a_serialiser_failure_is_reported() -> TestResult {
    assert!(matches!(
        render_with(&role("a", &[], &["/srv/a"]), &default_limits(), failing),
        Err(PolicyError::Serialize(_))
    ));
    Ok(())
}


#[test]
fn a_prefix_without_a_slash_is_left_alone() -> TestResult {
    assert_eq!(directory_of("/etc/cron.d/"), "/etc/cron.d");
    assert_eq!(directory_of("/etc/cron.d"), "/etc/cron.d");
    Ok(())
}
