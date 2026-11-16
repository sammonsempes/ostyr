use crate::support::{
    fixture, role, BIG_COUNT, DEFAULT_TABLE, MAX_PREFIX_PER_POLICY, MMAP_FLAGS, ONE_SELECTOR, OVER_CAP, RENAME_SOURCE, RENAME_TARGET, SMALL_CAP,
    SYMLINK_NAME, TOKEN_COUNT,
};
use crate::types::TestResult;
use linux_fim::error::PolicyError;
use linux_fim::limits::{default_limits, MAX_EQUAL_SELECTORS, MAX_POSTFIX_SELECTORS, MAX_SELECTOR_VALUES};
use linux_fim::model::{Kprobe, Limits, Role, TracingPolicy, WatchKind};
use linux_fim::policy::{
    ancestor_policy_name, ancestors_of, attribute_policy_name, build_policies, delete_policy_name, directory_of, full_name_policy_name,
    full_source_policy_name, full_target_policy_name, name_selectors, names_policy_name, parent_of, policy_name, policy_names, render_policy,
    render_with, reversed_ancestor_policy_name, reversed_names_policy_name, reversed_token_policy_name, slash_name_of, split_selectors,
    token_policy_name, union, unique, watch_selectors, HOOK_CHMOD, HOOK_CHOWN, HOOK_FILE_TRUNCATE, HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN,
    HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_REMOVEXATTR, HOOK_REMOVE_ACL, HOOK_RENAME, HOOK_RMDIR, HOOK_SETXATTR, HOOK_SET_ACL, HOOK_SYMLINK,
    HOOK_UNLINK, MAP_SHARED_MASK, MAY_WRITE_MASK,
};
use linux_fim::roles::load_roles;
use serde::ser::Error as SerError;
use serde_saphyr::SerializeError;
use std::fs;


const LINK_CREATED_INDEX: u32 = 2;


const LINK_DIR_INDEX: u32 = 1;


const RENAME_SOURCE_DIR: u32 = 0;


const RENAME_TARGET_DIR: u32 = 2;


const TOKEN_ONLY_EXTRA_POLICIES: usize = 5;


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
    assert_eq!(calls_of(&only_files, "ostyr-fimr-a")?, [HOOK_RENAME, HOOK_LINK]);
    assert_eq!(calls_of(&only_files, "ostyr-fimb-a")?, [HOOK_RENAME]);
    assert!(policy_of(&only_files, "ostyr-fimt-a").is_err());
    assert!(policy_of(&only_files, "ostyr-fimu-a").is_err());
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
    assert_eq!(calls_of(&tokens_only, "ostyr-fimu-a")?, [HOOK_RENAME, HOOK_LINK]);
    assert!(policy_of(&tokens_only, "ostyr-fimr-a").is_err());
    assert_eq!(
        build_policies(&tokens_only, &default_limits())?.len(),
        SMALL_CAP + TOKEN_ONLY_EXTRA_POLICIES
    );
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
            "ostyr-fimt-a",
            "ostyr-fimr-a",
            "ostyr-fimb-a",
            "ostyr-fimu-a",
            "ostyr-fimp-a",
            "ostyr-fimq-a",
            "ostyr-fimv-a"
        ]
    );
    assert_eq!(
        vec![
            policy_name("a"),
            names_policy_name("a"),
            ancestor_policy_name("a"),
            delete_policy_name("a"),
            attribute_policy_name("a"),
            token_policy_name("a"),
            reversed_names_policy_name("a"),
            reversed_ancestor_policy_name("a"),
            reversed_token_policy_name("a"),
            full_source_policy_name("a"),
            full_target_policy_name("a"),
            full_name_policy_name("a")
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


fn first_arg(probe: &Kprobe) -> Option<u32> {
    probe.args.first().map(|arg| arg.index)
}


fn listed(probe: &Kprobe) -> Vec<(u32, String)> {
    probe.args.iter().map(|arg| (arg.index, arg.arg_type.clone())).collect()
}


fn matched_indexes(probe: &Kprobe) -> Vec<u32> {
    unique_indexes(
        probe
            .selectors
            .iter()
            .flat_map(|selector| selector.match_args.iter().map(|arg| arg.index)),
    )
}


fn unique_indexes(indexes: impl Iterator<Item = u32>) -> Vec<u32> {
    indexes.fold(Vec::new(), |mut kept, index| {
        if !kept.contains(&index) {
            kept.push(index);
        }
        kept
    })
}


fn typed(pairs: &[(u32, &str)]) -> Vec<(u32, String)> {
    pairs.iter().map(|(index, arg_type)| (*index, (*arg_type).to_string())).collect()
}


#[test]
fn a_rename_is_matched_on_the_directory_and_name_listed_first_in_each_direction() -> TestResult {
    let server = named_role("server")?;
    let source_first = kprobe_in(&server, "ostyr-fimn-server", HOOK_RENAME)?;
    let target_first = kprobe_in(&server, "ostyr-fimr-server", HOOK_RENAME)?;
    assert_eq!(
        values_of(&source_first, RENAME_SOURCE_DIR, "Equal"),
        strings(&["/etc", "/root/.ssh", "/etc", "/root/.ssh"])
    );
    assert_eq!(
        values_of(&source_first, RENAME_SOURCE, "Postfix"),
        strings(&["/passwd", "/shadow", "/sudoers", "/ld.so.preload", "/authorized_keys"])
    );
    assert_eq!(
        values_of(&source_first, RENAME_SOURCE_DIR, "Prefix"),
        strings(&["/etc/cron.d", "/etc/systemd/system", "/usr/bin"])
    );
    assert_eq!(
        values_of(&target_first, RENAME_TARGET_DIR, "Equal"),
        values_of(&source_first, RENAME_SOURCE_DIR, "Equal")
    );
    assert_eq!(
        values_of(&target_first, RENAME_TARGET, "Postfix"),
        values_of(&source_first, RENAME_SOURCE, "Postfix")
    );
    assert_eq!(
        values_of(&target_first, RENAME_TARGET_DIR, "Prefix"),
        values_of(&source_first, RENAME_SOURCE_DIR, "Prefix")
    );
    assert_eq!(
        listed(&source_first),
        typed(&[
            (RENAME_SOURCE_DIR, "path"),
            (RENAME_SOURCE, "dentry"),
            (RENAME_TARGET_DIR, "path"),
            (RENAME_TARGET, "dentry")
        ])
    );
    assert_eq!(
        listed(&target_first),
        typed(&[
            (RENAME_TARGET_DIR, "path"),
            (RENAME_TARGET, "dentry"),
            (RENAME_SOURCE_DIR, "path"),
            (RENAME_SOURCE, "dentry")
        ])
    );
    assert_eq!(matched_indexes(&source_first), [RENAME_SOURCE_DIR, RENAME_SOURCE]);
    assert_eq!(matched_indexes(&target_first), [RENAME_TARGET_DIR, RENAME_TARGET]);
    assert_eq!(first_arg(&target_first), Some(RENAME_TARGET_DIR));
    Ok(())
}


#[test]
fn the_directories_above_watched_paths_are_matched_by_rename_and_rmdir() -> TestResult {
    let server = named_role("server")?;
    let directories = strings(&["/", "/root", "/etc", "/etc/systemd", "/usr"]);
    let names = strings(&["/etc", "/root", "/.ssh", "/cron.d", "/systemd", "/system", "/usr", "/bin"]);
    let rename = kprobe_in(&server, "ostyr-fima-server", HOOK_RENAME)?;
    assert_eq!(
        values_of(&rename, RENAME_SOURCE_DIR, "Equal"),
        [directories.clone(), directories].concat()
    );
    assert_eq!(values_of(&rename, RENAME_SOURCE, "Postfix"), names);
    let reversed = kprobe_in(&server, "ostyr-fimb-server", HOOK_RENAME)?;
    assert_eq!(values_of(&reversed, RENAME_TARGET, "Postfix"), names);
    assert_eq!(first_arg(&reversed), Some(RENAME_TARGET_DIR));
    let rmdir = kprobe_in(&server, "ostyr-fima-server", HOOK_RMDIR)?;
    assert_eq!(values_of(&rmdir, SYMLINK_NAME, "Postfix"), names);
    assert_eq!(values_of(&rmdir, 0, "Prefix").len(), TOKEN_COUNT - 1);
    assert_eq!(listed(&rmdir), typed(&[(0, "path"), (SYMLINK_NAME, "dentry")]));
    Ok(())
}


#[test]
fn honeytokens_and_their_directories_are_watched_by_the_honeytoken_policies() -> TestResult {
    let server = named_role("server")?;
    let rename = kprobe_in(&server, "ostyr-fimt-server", HOOK_RENAME)?;
    let moved = values_of(&rename, RENAME_SOURCE, "Postfix");
    assert_eq!(moved.first().map(String::as_str), Some("/credentials"));
    assert!(moved.contains(&"/.aws".to_string()) && moved.contains(&"/backups".to_string()));
    let reversed = kprobe_in(&server, "ostyr-fimu-server", HOOK_RENAME)?;
    assert_eq!(moved, values_of(&reversed, RENAME_TARGET, "Postfix"));
    assert_eq!(first_arg(&reversed), Some(RENAME_TARGET_DIR));
    let unlink = kprobe_in(&server, "ostyr-fimt-server", HOOK_UNLINK)?;
    assert_eq!(
        values_of(&unlink, SYMLINK_NAME, "Postfix"),
        strings(&["/credentials", "/id_rsa_backup", "/passwords.txt", "/.canary"])
    );
    assert_eq!(
        values_of(&unlink, 0, "Equal"),
        strings(&["/root/.aws", "/root/.ssh", "/root", "/var/backups"])
    );
    let link = kprobe_in(&server, "ostyr-fimt-server", HOOK_LINK)?;
    let created = kprobe_in(&server, "ostyr-fimu-server", HOOK_LINK)?;
    assert_eq!(values_of(&link, 0, "Postfix"), values_of(&created, LINK_CREATED_INDEX, "Postfix"));
    assert_eq!(values_of(&link, 0, "Postfix").len(), TOKEN_COUNT);
    assert_eq!(values_of(&created, LINK_DIR_INDEX, "Equal").len(), TOKEN_COUNT);
    assert_eq!(first_arg(&created), Some(LINK_DIR_INDEX));
    Ok(())
}


#[test]
fn hard_links_are_matched_by_each_name_listed_first() -> TestResult {
    let server = named_role("server")?;
    let link = kprobe_in(&server, "ostyr-fimn-server", HOOK_LINK)?;
    let created = kprobe_in(&server, "ostyr-fimr-server", HOOK_LINK)?;
    assert_eq!(values_of(&link, 0, "Postfix").first().map(String::as_str), Some("/passwd"));
    assert_eq!(
        values_of(&link, 0, "Prefix"),
        strings(&["/etc/cron.d/", "/etc/systemd/system/", "/usr/bin/"])
    );
    assert_eq!(values_of(&created, LINK_CREATED_INDEX, "Postfix"), values_of(&link, 0, "Postfix"));
    assert_eq!(
        values_of(&created, LINK_DIR_INDEX, "Prefix"),
        strings(&["/etc/cron.d", "/etc/systemd/system", "/usr/bin"])
    );
    assert_eq!(
        listed(&link),
        typed(&[(0, "dentry"), (LINK_DIR_INDEX, "path"), (LINK_CREATED_INDEX, "dentry")])
    );
    assert_eq!(
        listed(&created),
        typed(&[(LINK_DIR_INDEX, "path"), (LINK_CREATED_INDEX, "dentry"), (0, "dentry")])
    );
    assert_eq!(matched_indexes(&link), [0]);
    assert_eq!(matched_indexes(&created), [LINK_DIR_INDEX, LINK_CREATED_INDEX]);
    let symlink = kprobe_in(&server, "ostyr-fimn-server", HOOK_SYMLINK)?;
    assert_eq!(values_of(&symlink, 0, "Prefix").len(), TOKEN_COUNT - 1);
    Ok(())
}


#[test]
fn symlinks_are_matched_at_the_directories_above_what_is_watched() -> TestResult {
    let server = role("a", &[("/etc/cron.d/job", WatchKind::File)], &["/root/.ssh/id"]);
    let symlink = kprobe_in(&server, "ostyr-fimn-a", HOOK_SYMLINK)?;
    let names = values_of(&symlink, SYMLINK_NAME, "Postfix");
    assert!(["/job", "/etc", "/cron.d", "/root", "/.ssh"]
        .iter()
        .all(|wanted| names.contains(&wanted.to_string())));
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
        values_of(&setxattr, SYMLINK_NAME, "Postfix"),
        strings(&["/passwd", "/shadow", "/sudoers", "/ld.so.preload", "/authorized_keys"])
    );
    assert_eq!(values_of(&setxattr, SYMLINK_NAME, "Prefix").len(), TOKEN_COUNT - 1);
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
    let postfix = Limits {
        max_postfix_selectors: ONE_SELECTOR,
        ..default_limits()
    };
    assert!(matches!(
        render_policy(&server, &postfix),
        Err(PolicyError::TooManyMaps { ref operator, max: ONE_SELECTOR, .. }) if operator == "Postfix"
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
            assert!(selectors_with(policy, "Postfix") <= MAX_POSTFIX_SELECTORS, "{}", policy.metadata.name);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })
}


#[test]
fn a_path_is_split_into_its_directory_and_its_postfix_name() -> TestResult {
    assert_eq!(parent_of("/etc/passwd"), "/etc");
    assert_eq!(parent_of("/etc"), "/");
    assert_eq!(parent_of("etc"), "/");
    assert_eq!(slash_name_of("/etc/passwd"), "/passwd");
    assert_eq!(slash_name_of("passwd"), "/passwd");
    Ok(())
}


#[test]
fn directories_and_names_are_chunked_apart_and_prefixes_keep_the_directory_only() -> TestResult {
    let files = strings(&["/a/one", "/b/two", "/c/three", "/d/four", "/e/five"]);
    let selectors = split_selectors(0, 1, &files, &strings(&["/srv/tree/"]), SMALL_CAP);
    let exact = selectors.iter().filter(|selector| selector.match_args.len() == SMALL_CAP).count();
    assert_eq!(exact, OVER_CAP * OVER_CAP);
    let last: Option<Vec<Vec<String>>> = selectors
        .last()
        .map(|selector| selector.match_args.iter().map(|arg| arg.values.clone()).collect());
    assert_eq!(last, Some(vec![strings(&["/srv/tree"])]));
    assert_eq!(name_selectors(0, &[], &[], SMALL_CAP).len(), 0);
    assert_eq!(name_selectors(0, &files, &[], 0).len(), files.len());
    Ok(())
}


#[test]
fn the_full_path_policies_list_the_dentry_first_and_match_its_whole_path() -> TestResult {
    let server = named_role("server")?;
    let expected = [
        ("ostyr-fimp-server", [(HOOK_RENAME, RENAME_SOURCE), (HOOK_UNLINK, SYMLINK_NAME)]),
        ("ostyr-fimq-server", [(HOOK_RENAME, RENAME_TARGET), (HOOK_RMDIR, SYMLINK_NAME)]),
        ("ostyr-fimv-server", [(HOOK_SYMLINK, SYMLINK_NAME), (HOOK_LINK, LINK_CREATED_INDEX)]),
    ];
    for (name, hooks) in expected {
        for (call, dentry_index) in hooks {
            let probe = kprobe_in(&server, name, call)?;
            let first = probe.args.first().map(|arg| (arg.index, arg.arg_type.clone()));
            assert_eq!(first, Some((dentry_index, "dentry".to_string())), "{name} {call}");
            assert!(probe.selectors.iter().all(|selector| selector.match_args.len() == 1), "{name} {call}");
            assert!(probe
                .selectors
                .iter()
                .flat_map(|selector| selector.match_args.iter())
                .all(|arg| arg.index == dentry_index));
            let equal = values_of(&probe, dentry_index, "Equal");
            assert!(["/etc/passwd", "/root/.aws/credentials", "/root"]
                .iter()
                .all(|wanted| equal.iter().any(|value| value == wanted)));
            assert_eq!(
                values_of(&probe, dentry_index, "Prefix"),
                ["/etc/cron.d/", "/etc/systemd/system/", "/usr/bin/"],
                "{name} {call}"
            );
        }
    }
    Ok(())
}


#[test]
fn the_full_path_policies_stay_within_the_tetragon_caps_for_the_default_roles() -> TestResult {
    let limits = default_limits();
    let full = ["ostyr-fimp-", "ostyr-fimq-", "ostyr-fimv-"];
    for name in ["server", "workstation"] {
        for policy in build_policies(&named_role(name)?, &limits)? {
            if full.iter().any(|prefix| policy.metadata.name.starts_with(prefix)) {
                assert!(policy
                    .spec
                    .kprobes
                    .iter()
                    .all(|probe| probe.selectors.len() <= limits.max_kprobe_selectors));
                assert!(selectors_with(&policy, "Equal") <= limits.max_equal_selectors);
                assert!(selectors_with(&policy, "Prefix") <= limits.max_prefix_selectors);
            }
        }
    }
    Ok(())
}


#[test]
fn a_role_with_only_honeytokens_has_full_path_policies_without_a_prefix_selector() -> TestResult {
    let tokens_only = role("a", &[], &["/srv/a"]);
    let probe = kprobe_in(&tokens_only, "ostyr-fimp-a", HOOK_UNLINK)?;
    assert_eq!(values_of(&probe, SYMLINK_NAME, "Equal"), ["/srv/a", "/srv"]);
    assert!(values_of(&probe, SYMLINK_NAME, "Prefix").is_empty());
    Ok(())
}
