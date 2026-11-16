use crate::support::{
    fixture, role, BIG_COUNT, DEFAULT_TABLE, HONEYTOKENS, LINK_CREATED, MAX_PREFIX_SELECTORS, MMAP_FLAGS, MMAP_MATCHES, NAME_PREFIX_KPROBES,
    OVER_CAP, PREFIX_KPROBES, RENAME_TARGET, SMALL_CAP, SYMLINK_NAME, WATCHED_FILES, WATCHED_PREFIXES,
};
use crate::types::TestResult;
use linux_fim::error::PolicyError;
use linux_fim::limits::{default_limits, MAX_SELECTOR_VALUES};
use linux_fim::model::{Limits, Role, TracingPolicy, WatchKind};
use linux_fim::policy::{
    build_policies, directory_of, names_policy_name, policy_name, policy_names, render_policy, render_with, HOOK_CHMOD, HOOK_CHOWN,
    HOOK_FILE_TRUNCATE, HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_RENAME, HOOK_SYMLINK, MAP_SHARED_MASK,
    MAY_WRITE_MASK, PROT_WRITE_MASK,
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


fn calls_of(role: &Role, which: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(build_policies(role, &default_limits())?
        .into_iter()
        .nth(which)
        .ok_or("no such policy")?
        .spec
        .kprobes
        .into_iter()
        .map(|probe| probe.call)
        .collect())
}


fn calls(role: &Role) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    calls_of(role, 0)
}


fn name_calls(role: &Role) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    calls_of(role, 1)
}


fn kprobe_of(role: &Role, call: &str) -> Result<linux_fim::model::Kprobe, Box<dyn std::error::Error>> {
    build_policies(role, &default_limits())?
        .into_iter()
        .flat_map(|policy| policy.spec.kprobes)
        .find(|probe| probe.call == call)
        .ok_or_else(|| format!("no {call} kprobe").into())
}


fn values_of(probe: &linux_fim::model::Kprobe, index: u32, operator: &str) -> Vec<String> {
    probe
        .selectors
        .iter()
        .flat_map(|selector| selector.match_args.iter())
        .filter(|arg| arg.index == index && arg.operator == operator)
        .flat_map(|arg| arg.values.clone())
        .collect()
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
    let permission = kprobe_of(&named_role("server")?, HOOK_PERMISSION)?;
    assert!(permission.selectors.iter().all(|selector| selector
        .match_args
        .iter()
        .any(|arg| arg.operator == "Mask" && arg.values == [MAY_WRITE_MASK])));
    Ok(())
}


#[test]
fn only_files_give_permission_and_truncate_probes() -> TestResult {
    let only_files = role("a", &[("/etc/a", WatchKind::File)], &[]);
    assert_eq!(calls(&only_files)?, [HOOK_PERMISSION, HOOK_PATH_TRUNCATE, HOOK_FILE_TRUNCATE, HOOK_MMAP]);
    assert_eq!(name_calls(&only_files)?, [HOOK_RENAME, HOOK_SYMLINK, HOOK_LINK, HOOK_CHMOD, HOOK_CHOWN]);
    Ok(())
}


#[test]
fn prefixes_add_the_creation_probe_on_the_directory() -> TestResult {
    let only_prefix = role("a", &[("/etc/cron.d/", WatchKind::Prefix)], &[]);
    let policies = build_policies(&only_prefix, &default_limits())?;
    let mknod = kprobe_of(&only_prefix, HOOK_MKNOD)?;
    let values: Vec<&String> = mknod
        .selectors
        .iter()
        .flat_map(|selector| selector.match_args.iter().flat_map(|arg| arg.values.iter()))
        .collect();
    assert_eq!(values, ["/etc/cron.d"]);
    assert_eq!(
        policies.iter().map(|policy| policy.spec.kprobes.len()).collect::<Vec<usize>>(),
        [PREFIX_KPROBES, NAME_PREFIX_KPROBES]
    );
    Ok(())
}


#[test]
fn honeytokens_alone_give_one_open_probe() -> TestResult {
    let tokens_only = role("a", &[], &["/srv/a"]);
    assert_eq!(calls(&tokens_only)?, [HOOK_OPEN]);
    assert_eq!(name_calls(&tokens_only)?, [HOOK_LINK]);
    Ok(())
}


#[test]
fn the_policy_name_carries_the_role() -> TestResult {
    let names: Vec<String> = build_policies(&role("web-1", &[], &["/srv/a"]), &default_limits())?
        .into_iter()
        .map(|policy| policy.metadata.name)
        .collect();
    assert_eq!(names, ["ostyr-fim-web-1", "ostyr-fimn-web-1"]);
    assert_eq!(names, policy_names("web-1"));
    assert_eq!(
        (policy_name("a"), names_policy_name("a")),
        ("ostyr-fim-a".to_string(), "ostyr-fimn-a".to_string())
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


#[test]
fn names_are_watched_by_dentry_at_the_index_the_hook_reports() -> TestResult {
    let server = named_role("server")?;
    let rename = kprobe_of(&server, HOOK_RENAME)?;
    assert_eq!(
        values_of(&rename, RENAME_TARGET, "Equal").first().map(String::as_str),
        Some("/etc/passwd")
    );
    assert_eq!(
        values_of(&rename, RENAME_TARGET, "Prefix").first().map(String::as_str),
        Some("/etc/cron.d/")
    );
    let symlink = kprobe_of(&server, HOOK_SYMLINK)?;
    assert_eq!(values_of(&symlink, SYMLINK_NAME, "Prefix").len(), WATCHED_PREFIXES);
    let link = kprobe_of(&server, HOOK_LINK)?;
    assert_eq!(values_of(&link, 0, "Equal").len(), WATCHED_FILES + HONEYTOKENS);
    assert_eq!(values_of(&link, LINK_CREATED, "Prefix").len(), WATCHED_PREFIXES);
    Ok(())
}


#[test]
fn a_mapping_is_reported_only_when_shared_and_writable() -> TestResult {
    let mapping = kprobe_of(&named_role("server")?, HOOK_MMAP)?;
    assert!(mapping.selectors.iter().all(|selector| {
        selector.match_args.len() == MMAP_MATCHES
            && selector
                .match_args
                .iter()
                .any(|arg| arg.index == 1 && arg.operator == "Mask" && arg.values == [PROT_WRITE_MASK])
            && selector
                .match_args
                .iter()
                .any(|arg| arg.index == MMAP_FLAGS && arg.operator == "Mask" && arg.values == [MAP_SHARED_MASK])
    }));
    Ok(())
}


#[test]
fn no_policy_exceeds_the_prefix_selectors_tetragon_loads() -> TestResult {
    let server = build_policies(&named_role("server")?, &default_limits())?;
    let prefix_selectors: Vec<usize> = server
        .iter()
        .map(|policy| {
            policy
                .spec
                .kprobes
                .iter()
                .flat_map(|probe| probe.selectors.iter())
                .filter(|selector| selector.match_args.iter().any(|arg| arg.operator == "Prefix"))
                .count()
        })
        .collect();
    assert!(
        prefix_selectors.iter().all(|count| *count <= MAX_PREFIX_SELECTORS),
        "{prefix_selectors:?}"
    );
    Ok(())
}
