use crate::support::{
    fixture, role, BIG_COUNT, DEFAULT_TABLE, MAX_PREFIX_PER_POLICY, MMAP_FLAGS, ONE_SELECTOR, OVER_CAP, RENAME_SOURCE, RENAME_TARGET, SMALL_CAP,
    SYMLINK_NAME, TOKEN_COUNT,
};
use crate::types::TestResult;
use linux_fim::error::PolicyError;
use linux_fim::limits::{default_limits, MAX_EQUAL_SELECTORS, MAX_SELECTOR_VALUES};
use linux_fim::model::{Kprobe, Limits, Role, TracingPolicy, WatchKind};
use linux_fim::policy::{
    ancestor_policy_name, ancestors_of, attribute_policy_name, build_policies, delete_policy_name, directory_of, names_policy_name, policy_name,
    policy_names, render_policy, render_with, token_policy_name, union, unique, watch_selectors, HOOK_CHMOD, HOOK_CHOWN, HOOK_FILE_TRUNCATE,
    HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_REMOVEXATTR, HOOK_REMOVE_ACL, HOOK_RENAME, HOOK_RMDIR,
    HOOK_SETXATTR, HOOK_SET_ACL, HOOK_SYMLINK, HOOK_UNLINK, MAP_SHARED_MASK, MAY_WRITE_MASK,
};
use linux_fim::roles::load_roles;
use serde::ser::Error as SerError;
use serde_saphyr::SerializeError;
use std::fs;


const LINK_CREATED_INDEX: u32 = 2;


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


fn policy_of(role: &Role, name: &str) -> Result<TracingPolicy, Box<dyn std::error::Error>> {
    build_policies(role, &default_limits())?
        .into_iter()
        .find(|policy| policy.metadata.name == name)
        .ok_or_else(|| format!("no policy {name}").into())
}


fn calls_of(role: &Role, name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(policy_of(role, name)?.spec.kprobes.into_iter().map(|probe| probe.call).collect())
}


fn kprobe_in(role: &Role, name: &str, call: &str) -> Result<Kprobe, Box<dyn std::error::Error>> {
    policy_of(role, name)?
        .spec
        .kprobes
        .into_iter()
        .find(|probe| probe.call == call)
        .ok_or_else(|| format!("no {call} kprobe").into())
}


fn values_of(probe: &Kprobe, index: u32, operator: &str) -> Vec<String> {
    probe
        .selectors
        .iter()
        .flat_map(|selector| selector.match_args.iter())
        .filter(|arg| arg.index == index && arg.operator == operator)
        .flat_map(|arg| arg.values.clone())
        .collect()
}


fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}


fn selectors_with(policy: &TracingPolicy, operator: &str) -> usize {
    policy
        .spec
        .kprobes
        .iter()
        .flat_map(|probe| probe.selectors.iter())
        .filter(|selector| selector.match_args.iter().any(|arg| arg.operator == operator))
        .count()
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
    let permission = kprobe_in(&named_role("server")?, "ostyr-fim-server", HOOK_PERMISSION)?;
    assert!(permission.selectors.iter().all(|selector| selector
        .match_args
        .iter()
        .any(|arg| arg.operator == "Mask" && arg.values == [MAY_WRITE_MASK])));
    Ok(())
}


#[test]
fn only_files_give_every_probe_but_the_prefix_and_honeytoken_ones() -> TestResult {
    let only_files = role("a", &[("/etc/a", WatchKind::File)], &[]);
    assert_eq!(
        calls_of(&only_files, "ostyr-fim-a")?,
        [HOOK_PERMISSION, HOOK_PATH_TRUNCATE, HOOK_FILE_TRUNCATE, HOOK_MMAP]
    );
    assert_eq!(calls_of(&only_files, "ostyr-fimn-a")?, [HOOK_RENAME, HOOK_SYMLINK, HOOK_LINK]);
    assert_eq!(calls_of(&only_files, "ostyr-fima-a")?, [HOOK_RENAME, HOOK_RMDIR]);
    assert_eq!(calls_of(&only_files, "ostyr-fimd-a")?, [HOOK_UNLINK, HOOK_CHMOD, HOOK_CHOWN]);
    assert_eq!(
        calls_of(&only_files, "ostyr-fimx-a")?,
        [HOOK_SETXATTR, HOOK_REMOVEXATTR, HOOK_SET_ACL, HOOK_REMOVE_ACL]
    );
    assert!(policy_of(&only_files, "ostyr-fimt-a").is_err());
    Ok(())
}


#[test]
fn prefixes_add_the_creation_probe_on_the_directory() -> TestResult {
    let only_prefix = role("a", &[("/etc/cron.d/", WatchKind::Prefix)], &[]);
    let mknod = kprobe_in(&only_prefix, "ostyr-fim-a", HOOK_MKNOD)?;
    let values: Vec<&String> = mknod
        .selectors
        .iter()
        .flat_map(|selector| selector.match_args.iter().flat_map(|arg| arg.values.iter()))
        .collect();
    assert_eq!(values, ["/etc/cron.d"]);
    assert_eq!(calls_of(&only_prefix, "ostyr-fimn-a")?, [HOOK_RENAME, HOOK_SYMLINK, HOOK_LINK]);
    Ok(())
}


#[test]
fn honeytokens_alone_give_an_open_probe_and_a_honeytoken_policy() -> TestResult {
    let tokens_only = role("a", &[], &["/srv/a"]);
    assert_eq!(calls_of(&tokens_only, "ostyr-fim-a")?, [HOOK_OPEN]);
    assert_eq!(calls_of(&tokens_only, "ostyr-fimt-a")?, [HOOK_RENAME, HOOK_UNLINK, HOOK_RMDIR, HOOK_LINK]);
    assert_eq!(calls_of(&tokens_only, "ostyr-fimn-a")?, [HOOK_SYMLINK]);
    assert_eq!(build_policies(&tokens_only, &default_limits())?.len(), SMALL_CAP + 1);
    Ok(())
}


#[test]
fn the_policy_names_carry_the_role_and_never_collide() -> TestResult {
    let names: Vec<String> = build_policies(&named_role("server")?, &default_limits())?
        .into_iter()
        .map(|policy| policy.metadata.name)
        .collect();
    assert_eq!(names, policy_names("server"));
    assert_eq!(
        policy_names("a"),
        [
            "ostyr-fim-a",
            "ostyr-fimn-a",
            "ostyr-fima-a",
            "ostyr-fimd-a",
            "ostyr-fimx-a",
            "ostyr-fimt-a"
        ]
    );
    assert_eq!(
        vec![
            policy_name("a"),
            names_policy_name("a"),
            ancestor_policy_name("a"),
            delete_policy_name("a"),
            attribute_policy_name("a"),
            token_policy_name("a")
        ],
        policy_names("a")
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
fn a_rename_is_matched_as_source_and_as_target_for_files_and_prefixes() -> TestResult {
    let rename = kprobe_in(&named_role("server")?, "ostyr-fimn-server", HOOK_RENAME)?;
    [RENAME_SOURCE, RENAME_TARGET].iter().for_each(|index| {
        assert_eq!(values_of(&rename, *index, "Equal").first().map(String::as_str), Some("/etc/passwd"));
        assert_eq!(values_of(&rename, *index, "Prefix").first().map(String::as_str), Some("/etc/cron.d/"));
    });
    assert_eq!(
        rename.args.iter().map(|arg| arg.index).collect::<Vec<u32>>(),
        [RENAME_SOURCE, RENAME_TARGET]
    );
    Ok(())
}


#[test]
fn the_directories_above_watched_paths_are_matched_by_rename_and_rmdir() -> TestResult {
    let server = named_role("server")?;
    let expected = strings(&[
        "/etc",
        "/root",
        "/root/.ssh",
        "/etc/cron.d",
        "/etc/systemd",
        "/etc/systemd/system",
        "/usr",
        "/usr/bin",
    ]);
    let rename = kprobe_in(&server, "ostyr-fima-server", HOOK_RENAME)?;
    assert_eq!(values_of(&rename, RENAME_SOURCE, "Equal"), expected);
    assert_eq!(values_of(&rename, RENAME_TARGET, "Equal"), expected);
    let rmdir = kprobe_in(&server, "ostyr-fima-server", HOOK_RMDIR)?;
    assert_eq!(values_of(&rmdir, SYMLINK_NAME, "Equal"), expected);
    assert_eq!(values_of(&rmdir, SYMLINK_NAME, "Prefix").len(), TOKEN_COUNT - 1);
    Ok(())
}


#[test]
fn honeytokens_and_their_directories_are_watched_by_the_honeytoken_policy() -> TestResult {
    let server = named_role("server")?;
    let rename = kprobe_in(&server, "ostyr-fimt-server", HOOK_RENAME)?;
    let moved = values_of(&rename, RENAME_SOURCE, "Equal");
    assert_eq!(moved.first().map(String::as_str), Some("/root/.aws/credentials"));
    assert!(moved.contains(&"/root/.aws".to_string()) && moved.contains(&"/var/backups".to_string()));
    assert_eq!(moved, values_of(&rename, RENAME_TARGET, "Equal"));
    let unlink = kprobe_in(&server, "ostyr-fimt-server", HOOK_UNLINK)?;
    assert_eq!(values_of(&unlink, SYMLINK_NAME, "Equal").len(), TOKEN_COUNT);
    let link = kprobe_in(&server, "ostyr-fimt-server", HOOK_LINK)?;
    assert_eq!(values_of(&link, 0, "Equal"), values_of(&link, LINK_CREATED_INDEX, "Equal"));
    assert_eq!(values_of(&link, 0, "Equal").len(), TOKEN_COUNT);
    Ok(())
}


#[test]
fn hard_links_are_matched_by_both_names() -> TestResult {
    let server = named_role("server")?;
    let link = kprobe_in(&server, "ostyr-fimn-server", HOOK_LINK)?;
    assert_eq!(values_of(&link, 0, "Equal").first().map(String::as_str), Some("/etc/passwd"));
    assert_eq!(values_of(&link, LINK_CREATED_INDEX, "Equal"), values_of(&link, 0, "Equal"));
    assert_eq!(values_of(&link, 0, "Prefix"), values_of(&link, LINK_CREATED_INDEX, "Prefix"));
    let symlink = kprobe_in(&server, "ostyr-fimn-server", HOOK_SYMLINK)?;
    assert_eq!(values_of(&symlink, SYMLINK_NAME, "Prefix").len(), TOKEN_COUNT - 1);
    Ok(())
}


#[test]
fn symlinks_are_matched_at_the_directories_above_what_is_watched() -> TestResult {
    let server = role("a", &[("/etc/cron.d/job", WatchKind::File)], &["/root/.ssh/id"]);
    let symlink = kprobe_in(&server, "ostyr-fimn-a", HOOK_SYMLINK)?;
    let values = values_of(&symlink, SYMLINK_NAME, "Equal");
    assert!(["/etc/cron.d/job", "/etc", "/etc/cron.d", "/root", "/root/.ssh"]
        .iter()
        .all(|wanted| values.contains(&wanted.to_string())));
    Ok(())
}


#[test]
fn a_shared_mapping_is_reported_whatever_its_protection() -> TestResult {
    let mapping = kprobe_in(&named_role("server")?, "ostyr-fim-server", HOOK_MMAP)?;
    assert!(mapping.selectors.iter().all(|selector| {
        selector.match_args.len() == SMALL_CAP
            && selector
                .match_args
                .iter()
                .any(|arg| arg.index == MMAP_FLAGS && arg.operator == "Mask" && arg.values == [MAP_SHARED_MASK])
    }));
    Ok(())
}


#[test]
fn attribute_hooks_match_the_dentry_and_the_acl_ones_tolerate_older_kernels() -> TestResult {
    let server = named_role("server")?;
    let tolerant: Vec<(String, bool)> = policy_of(&server, "ostyr-fimx-server")?
        .spec
        .kprobes
        .into_iter()
        .map(|probe| (probe.call, probe.ignore.call_not_found))
        .collect();
    assert_eq!(
        tolerant,
        [
            (HOOK_SETXATTR.to_string(), false),
            (HOOK_REMOVEXATTR.to_string(), false),
            (HOOK_SET_ACL.to_string(), true),
            (HOOK_REMOVE_ACL.to_string(), true)
        ]
    );
    let setxattr = kprobe_in(&server, "ostyr-fimx-server", HOOK_SETXATTR)?;
    assert_eq!(
        values_of(&setxattr, SYMLINK_NAME, "Equal").first().map(String::as_str),
        Some("/etc/passwd")
    );
    Ok(())
}


#[test]
fn values_are_chunked_by_the_cap_and_a_zero_cap_means_one() -> TestResult {
    let nine = paths("/etc/f", "", BIG_COUNT);
    let chunked = watch_selectors(0, &nine, &[], &[], MAX_SELECTOR_VALUES);
    assert_eq!(chunked.len(), SMALL_CAP);
    assert_eq!(watch_selectors(0, &nine, &[], &[], 0).len(), BIG_COUNT);
    Ok(())
}


#[test]
fn ancestors_unique_and_union_are_deterministic() -> TestResult {
    assert_eq!(ancestors_of("/etc/cron.d/job"), ["/etc", "/etc/cron.d"]);
    assert!(ancestors_of("/etc").is_empty());
    assert!(ancestors_of("/").is_empty());
    assert_eq!(unique(strings(&["/a", "/b", "/a"]).into_iter()), ["/a", "/b"]);
    assert_eq!(union(&strings(&["/a", "/b"]), &strings(&["/b", "/c"])), ["/a", "/b", "/c"]);
    Ok(())
}


#[test]
fn a_kprobe_needing_more_selectors_than_tetragon_takes_is_refused() -> TestResult {
    let limits = Limits {
        max_kprobe_selectors: ONE_SELECTOR,
        ..default_limits()
    };
    assert!(matches!(
        render_policy(&named_role("server")?, &limits),
        Err(PolicyError::TooManySelectors { max: ONE_SELECTOR, .. })
    ));
    Ok(())
}


#[test]
fn a_policy_needing_more_string_maps_than_tetragon_loads_is_refused() -> TestResult {
    let server = named_role("server")?;
    let equal = Limits {
        max_equal_selectors: ONE_SELECTOR,
        ..default_limits()
    };
    let prefix = Limits {
        max_prefix_selectors: ONE_SELECTOR,
        ..default_limits()
    };
    assert!(matches!(
        render_policy(&server, &equal),
        Err(PolicyError::TooManyMaps { ref operator, max: ONE_SELECTOR, .. }) if operator == "Equal"
    ));
    assert!(matches!(
        render_policy(&server, &prefix),
        Err(PolicyError::TooManyMaps { ref operator, max: ONE_SELECTOR, .. }) if operator == "Prefix"
    ));
    Ok(())
}


#[test]
fn no_default_policy_exceeds_the_string_maps_tetragon_loads() -> TestResult {
    ["server", "workstation"].iter().try_for_each(|name| {
        build_policies(&named_role(name)?, &default_limits())?.iter().try_for_each(|policy| {
            assert!(selectors_with(policy, "Equal") <= MAX_EQUAL_SELECTORS, "{}", policy.metadata.name);
            assert!(selectors_with(policy, "Prefix") <= MAX_PREFIX_PER_POLICY, "{}", policy.metadata.name);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })
}
