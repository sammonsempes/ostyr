use crate::support::{role, DEFAULT_TABLE, LAST_INDEX, SMALL_CAP, UNSUPPORTED_VERSION};
use crate::types::TestResult;
use linux_fim::error::{PathError, RoleError, TableError};
use linux_fim::limits::{default_limits, MAX_PATH_BYTES, MAX_ROLE_NAME_BYTES};
use linux_fim::model::{Honeytoken, HoneytokenKind, Limits, Role, WatchKind};
use linux_fim::roles::{check_name, check_path, check_role, first_duplicate, load_roles};
use std::fs;


const VALID: &str = "version: 1\nroles:\n  - name: a\n    watched:\n      - { path: /etc/passwd, kind: file }\n";


fn table_with(roles: &str) -> String {
    format!("version: 1\nroles:\n{roles}")
}


#[test]
fn default_table_loads() -> TestResult {
    let table = load_roles(&fs::read_to_string(DEFAULT_TABLE)?, &default_limits())?;
    let names: Vec<&str> = table.roles.iter().map(|role| role.name.as_str()).collect();
    assert_eq!(names, ["server", "workstation"]);
    assert!(table.roles.iter().all(|role| !role.watched.is_empty() && !role.honeytokens.is_empty()));
    Ok(())
}


#[test]
fn a_minimal_table_loads_with_empty_lists() -> TestResult {
    let table = load_roles(VALID, &default_limits())?;
    assert!(table.roles.iter().all(|role| role.honeytokens.is_empty()));
    Ok(())
}


#[test]
fn an_oversized_table_is_refused_before_parsing() -> TestResult {
    let limits = Limits {
        max_table_bytes: SMALL_CAP,
        ..default_limits()
    };
    assert!(matches!(load_roles(VALID, &limits), Err(TableError::TooLarge { max: SMALL_CAP, .. })));
    Ok(())
}


#[test]
fn a_table_at_the_cap_is_accepted() -> TestResult {
    let limits = Limits {
        max_table_bytes: VALID.len(),
        ..default_limits()
    };
    load_roles(VALID, &limits)?;
    Ok(())
}


#[test]
fn invalid_yaml_and_unknown_keys_are_refused() -> TestResult {
    let unknown_key = format!("{VALID}    surprise: 1\n");
    assert!(matches!(load_roles("version: [", &default_limits()), Err(TableError::Parse(_))));
    assert!(matches!(load_roles(&unknown_key, &default_limits()), Err(TableError::Parse(_))));
    Ok(())
}


#[test]
fn an_unknown_version_is_refused() -> TestResult {
    let text = VALID.replace("version: 1", "version: 2");
    assert!(matches!(
        load_roles(&text, &default_limits()),
        Err(TableError::Version { found: UNSUPPORTED_VERSION })
    ));
    Ok(())
}


#[test]
fn too_many_roles_are_refused() -> TestResult {
    let limits = Limits {
        max_roles: 1,
        ..default_limits()
    };
    let text = table_with("  - { name: a }\n  - { name: b }\n");
    assert!(matches!(
        load_roles(&text, &limits),
        Err(TableError::TooManyRoles { count: SMALL_CAP, max: 1 })
    ));
    Ok(())
}


#[test]
fn a_bad_role_names_its_index() -> TestResult {
    let text = table_with("  - { name: a }\n  - { name: Bad }\n");
    assert!(matches!(
        load_roles(&text, &default_limits()),
        Err(TableError::Role {
            index: 1,
            source: RoleError::Name { .. }
        })
    ));
    Ok(())
}


#[test]
fn a_repeated_role_name_names_both_indexes() -> TestResult {
    let text = table_with("  - { name: a }\n  - { name: b }\n  - { name: a }\n");
    assert!(matches!(
        load_roles(&text, &default_limits()),
        Err(TableError::DuplicateRole { index: LAST_INDEX, first: 0 })
    ));
    Ok(())
}


#[test]
fn role_names_follow_the_grammar() -> TestResult {
    let long = "a".repeat(MAX_ROLE_NAME_BYTES + 1);
    let longest = "a".repeat(MAX_ROLE_NAME_BYTES);
    let refused = ["", "Server", "-a", "a-", "1a", "a_b", "a b", long.as_str()];
    assert!(refused.iter().all(|name| check_name(name).is_err()));
    assert!(["a", "web-server1", longest.as_str()].iter().all(|name| check_name(name).is_ok()));
    Ok(())
}


#[test]
fn watched_and_honeytoken_counts_are_capped() -> TestResult {
    let limits = Limits {
        max_watched: 1,
        max_honeytokens: 1,
        ..default_limits()
    };
    let many_watched = role("a", &[("/etc/a", WatchKind::File), ("/etc/b", WatchKind::File)], &[]);
    let many_tokens = role("a", &[], &["/srv/a", "/srv/b"]);
    assert!(matches!(
        check_role(&many_watched, &limits),
        Err(RoleError::TooManyWatched { count: SMALL_CAP, max: 1 })
    ));
    assert!(matches!(
        check_role(&many_tokens, &limits),
        Err(RoleError::TooManyHoneytokens { count: SMALL_CAP, max: 1 })
    ));
    Ok(())
}


#[test]
fn a_bad_path_names_its_index() -> TestResult {
    let watched = role("a", &[("/etc/a", WatchKind::File), ("etc/b", WatchKind::File)], &[]);
    let token = role("a", &[], &["/srv/a", "/srv/b/"]);
    assert!(matches!(
        check_role(&watched, &default_limits()),
        Err(RoleError::Watched {
            index: 1,
            source: PathError::NotAbsolute
        })
    ));
    assert!(matches!(
        check_role(&token, &default_limits()),
        Err(RoleError::Honeytoken {
            index: 1,
            source: PathError::Kind
        })
    ));
    Ok(())
}


#[test]
fn duplicates_name_both_indexes() -> TestResult {
    let watched = role(
        "a",
        &[("/etc/a", WatchKind::File), ("/etc/b", WatchKind::File), ("/etc/a", WatchKind::File)],
        &[],
    );
    let tokens = role("a", &[], &["/srv/a", "/srv/b", "/srv/b"]);
    assert!(matches!(
        check_role(&watched, &default_limits()),
        Err(RoleError::DuplicateWatched { index: LAST_INDEX, first: 0 })
    ));
    assert!(matches!(
        check_role(&tokens, &default_limits()),
        Err(RoleError::DuplicateHoneytoken { index: LAST_INDEX, first: 1 })
    ));
    Ok(())
}


#[test]
fn a_role_that_repeats_nothing_is_accepted() -> TestResult {
    check_role(
        &role("a", &[("/etc/a", WatchKind::File), ("/etc/b/", WatchKind::Prefix)], &["/srv/a"]),
        &default_limits(),
    )?;
    Ok(())
}


#[test]
fn every_path_refusal_is_reported() -> TestResult {
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    let cases = [
        (long.as_str(), WatchKind::File, "too long"),
        ("etc/passwd", WatchKind::File, "relative"),
        ("/etc/*/passwd", WatchKind::File, "glob in the middle"),
        ("/etc/pass wd", WatchKind::File, "space"),
        ("/etc/pässwd", WatchKind::File, "non ASCII"),
        ("/", WatchKind::Prefix, "root"),
        ("/etc/../shadow", WatchKind::File, "dot dot"),
        ("/etc/./shadow", WatchKind::File, "dot"),
        ("/etc//shadow", WatchKind::File, "empty component"),
        ("//", WatchKind::Prefix, "double slash prefix"),
        ("/etc/cron.d", WatchKind::Prefix, "prefix without slash"),
        ("/etc/passwd/", WatchKind::File, "file with slash"),
    ];
    let outcomes: Vec<bool> = cases
        .iter()
        .map(|(path, kind, _)| check_path(path, *kind, MAX_PATH_BYTES).is_err())
        .collect();
    assert!(outcomes.iter().all(|refused| *refused), "{outcomes:?}");
    Ok(())
}


#[test]
fn each_path_refusal_has_its_own_variant() -> TestResult {
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
    assert!(matches!(
        check_path(&long, WatchKind::File, MAX_PATH_BYTES),
        Err(PathError::TooLong { .. })
    ));
    assert!(matches!(check_path("a", WatchKind::File, MAX_PATH_BYTES), Err(PathError::NotAbsolute)));
    assert!(matches!(check_path("/a*", WatchKind::File, MAX_PATH_BYTES), Err(PathError::Character)));
    assert!(matches!(check_path("/", WatchKind::Prefix, MAX_PATH_BYTES), Err(PathError::Root)));
    assert!(matches!(
        check_path("/a/../b", WatchKind::File, MAX_PATH_BYTES),
        Err(PathError::Component)
    ));
    assert!(matches!(check_path("/a/", WatchKind::File, MAX_PATH_BYTES), Err(PathError::Kind)));
    assert!(matches!(check_path("/a", WatchKind::Prefix, MAX_PATH_BYTES), Err(PathError::Kind)));
    Ok(())
}


#[test]
fn good_paths_are_accepted() -> TestResult {
    check_path("/etc/ld.so.preload", WatchKind::File, MAX_PATH_BYTES)?;
    check_path("/etc/cron.d/", WatchKind::Prefix, MAX_PATH_BYTES)?;
    check_path("/home/a+b@c/x-y_z", WatchKind::File, MAX_PATH_BYTES)?;
    Ok(())
}


#[test]
fn first_duplicate_finds_the_second_occurrence() -> TestResult {
    assert_eq!(first_duplicate(&["a", "b", "a", "b"]), Some((LAST_INDEX, 0)));
    assert_eq!(first_duplicate(&["a", "b"]), None);
    assert_eq!(first_duplicate(&[]), None);
    Ok(())
}


#[test]
fn honeytoken_kinds_deserialize() -> TestResult {
    let text = "version: 1\nroles:\n  - name: a\n    honeytokens:\n      - { path: /a, kind: canary }\n      - { path: /b, kind: aws_credentials }\n      - { path: /c, kind: ssh_key }\n      - { path: /d, kind: password_file }\n";
    let table = load_roles(text, &default_limits())?;
    let kinds: Vec<HoneytokenKind> = table
        .roles
        .iter()
        .flat_map(|item: &Role| item.honeytokens.iter().map(|token: &Honeytoken| token.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            HoneytokenKind::Canary,
            HoneytokenKind::AwsCredentials,
            HoneytokenKind::SshKey,
            HoneytokenKind::PasswordFile
        ]
    );
    Ok(())
}
