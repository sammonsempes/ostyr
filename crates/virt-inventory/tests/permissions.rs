#[path = "common/perms.rs"]
mod perms;
#[path = "common/types.rs"]
mod types;


use perms::permissions;
use std::collections::BTreeMap;
use types::TestResult;
use virt_inventory::error::{ParseError, ReadOnlyError};
use virt_inventory::limits::Limits;
use virt_inventory::model::{PathPrivileges, Permissions};
use virt_inventory::proxmox::parse_permissions;
use virt_inventory::readonly::{check_read_only, MAX_REPORTED};


const NEST_DEPTH: usize = 1_000_000;


const SMALL_PATHS: usize = 2;


const SMALL_PRIVILEGES: usize = 3;


const SMALL_GRANTS: usize = 4;


const OVER_REPORTED: usize = 40;


const HUGE_PATHS: usize = 100_000;


const HUGE_PRIVILEGES: usize = 10_000;


const FLAG_TWO: u64 = 2;


const NAME_LIMIT: usize = 64;


const GRANTS_SEEN: usize = 6;


const FIRST_PAIR: &[(&str, u64)] = &[("VM.Audit", 1), ("Sys.Audit", 1)];


const SECOND_PAIR: &[(&str, u64)] = &[("Datastore.Audit", 1), ("SDN.Audit", 1), ("Pool.Audit", 1), ("Mapping.Audit", 1)];


const AUDITOR: &[(&str, u64)] = &[
    ("VM.Audit", 1),
    ("Sys.Audit", 1),
    ("Datastore.Audit", 1),
    ("SDN.Audit", 1),
    ("Pool.Audit", 1),
    ("Mapping.Audit", 1),
];


fn parsed(paths: &[(&str, &[(&str, u64)])]) -> Result<Permissions, ParseError> {
    parse_permissions(permissions(paths).as_slice(), &Limits::default())
}


fn entry(path: &str, names: &[&str]) -> PathPrivileges {
    PathPrivileges {
        path: path.to_owned(),
        privileges: names.iter().map(|name| ((*name).to_owned(), 1)).collect::<BTreeMap<_, _>>(),
    }
}


fn verdict(paths: &[(&str, &[(&str, u64)])]) -> Result<Result<(), ReadOnlyError>, ParseError> {
    parsed(paths).map(|found| check_read_only(&found))
}


fn refusal_of(privilege: &str) -> Result<(), ReadOnlyError> {
    Err(ReadOnlyError::HasWriteRights {
        privileges: vec![privilege.to_owned()],
        omitted: 0,
    })
}


#[test]
fn the_allowlisted_privileges_only_are_read_only() -> TestResult {
    assert_eq!(verdict(&[("/", AUDITOR)])?, Ok(()));
    assert_eq!(verdict(&[("/", FIRST_PAIR), ("/vms/100", SECOND_PAIR)])?, Ok(()));
    Ok(())
}


#[test]
fn a_write_privilege_is_refused_by_name() -> TestResult {
    assert_eq!(verdict(&[("/", AUDITOR), ("/vms", &[("VM.PowerMgmt", 1)])])?, refusal_of("VM.PowerMgmt"));
    Ok(())
}


#[test]
fn an_unknown_privilege_is_refused() -> TestResult {
    assert_eq!(verdict(&[("/", &[("VM.Audit", 1), ("Foo.Bar", 1)])])?, refusal_of("Foo.Bar"));
    Ok(())
}


#[test]
fn vm_monitor_is_not_read_only() -> TestResult {
    assert_eq!(verdict(&[("/", &[("VM.Audit", 1), ("VM.Monitor", 1)])])?, refusal_of("VM.Monitor"));
    Ok(())
}


#[test]
fn a_privilege_listed_with_flag_zero_still_counts() -> TestResult {
    let found = parsed(&[("/", &[("VM.Audit", 1), ("VM.Allocate", 0)])])?;
    assert_eq!(found.paths.first().ok_or("no path")?.privileges.get("VM.Allocate"), Some(&0));
    assert_eq!(check_read_only(&found), refusal_of("VM.Allocate"));
    Ok(())
}


#[test]
fn no_privilege_at_all_is_refused() -> TestResult {
    assert_eq!(verdict(&[])?, Err(ReadOnlyError::NoRights));
    assert_eq!(verdict(&[("/", &[])])?, Err(ReadOnlyError::NoRights));
    assert!(ReadOnlyError::NoRights.to_string().contains("no privilege"));
    Ok(())
}


#[test]
fn many_refused_privileges_are_cut_with_a_visible_count() -> TestResult {
    let names = (0..OVER_REPORTED).map(|index| format!("X.P{index:02}")).collect::<Vec<_>>();
    let found = Permissions {
        paths: vec![entry("/", &names.iter().map(String::as_str).collect::<Vec<_>>())],
    };
    let refused = check_read_only(&found).err().ok_or("passed")?;
    assert!(matches!(
        &refused,
        ReadOnlyError::HasWriteRights { privileges, omitted } if privileges.len() == MAX_REPORTED && *omitted == OVER_REPORTED - MAX_REPORTED
    ));
    assert!(refused.to_string().contains("8 more"));
    Ok(())
}


#[test]
fn bad_paths_names_and_flags_refuse_the_whole_answer() -> TestResult {
    let long_name = format!("A{}", "b".repeat(NAME_LIMIT));
    let refused = [
        permissions(&[("vms", &[("VM.Audit", 1)])]),
        permissions(&[("/a\nb", &[("VM.Audit", 1)])]),
        permissions(&[("/", &[("VM Audit", 1)])]),
        permissions(&[("/", &[("", 1)])]),
        permissions(&[("/", &[("-VM.Audit", 1)])]),
        permissions(&[("/", &[("VM.Audit", FLAG_TWO)])]),
        permissions(&[("/", &[(long_name.as_str(), 1)])]),
    ];
    refused.iter().for_each(|input| {
        assert!(matches!(
            parse_permissions(input.as_slice(), &Limits::default()),
            Err(ParseError::BadPermission)
        ))
    });
    assert!(ParseError::BadPermission.to_string().contains("refused"));
    Ok(())
}


#[test]
fn a_privilege_name_of_the_maximum_length_is_accepted() -> TestResult {
    let name = format!("A{}", "b".repeat(NAME_LIMIT - 1));
    let found = parsed(&[("/", &[(name.as_str(), 1)])])?;
    assert_eq!(found.paths.first().ok_or("no path")?.privileges.len(), 1);
    Ok(())
}


#[test]
fn malformed_answers_are_refused_with_a_position() -> TestResult {
    let limits = Limits::default();
    let broken = [
        b"nope".as_slice(),
        b"{}".as_slice(),
        br#"{"data":[]}"#.as_slice(),
        br#"{"data":{"/":[]}}"#.as_slice(),
        br#"{"data":{"/":{"VM.Audit":true}}}"#.as_slice(),
        br#"{"data":{"/":{"VM.Audit":-1}}}"#.as_slice(),
        br#"{"data":{"/":1}}"#.as_slice(),
    ];
    broken
        .iter()
        .for_each(|input| assert!(matches!(parse_permissions(*input, &limits), Err(ParseError::Malformed { .. }))));
    Ok(())
}


#[test]
fn counts_are_refused_before_anything_is_built() -> TestResult {
    let limits = Limits {
        max_paths: SMALL_PATHS,
        max_privileges: SMALL_PRIVILEGES,
        max_grants: SMALL_GRANTS,
        ..Limits::default()
    };
    let one: &[(&str, u64)] = &[("VM.Audit", 1)];
    let three: &[(&str, u64)] = &[("VM.Audit", 1), ("Sys.Audit", 1), ("Pool.Audit", 1)];
    let four: &[(&str, u64)] = &[("VM.Audit", 1), ("Sys.Audit", 1), ("Pool.Audit", 1), ("SDN.Audit", 1)];
    assert!(parse_permissions(permissions(&[("/a", one), ("/b", three)]).as_slice(), &limits).is_ok());
    let too_many_paths = parse_permissions(permissions(&[("/a", one), ("/b", one), ("/c", one)]).as_slice(), &limits);
    assert!(matches!(too_many_paths, Err(ParseError::TooManyItems { count, max }) if count == SMALL_PATHS + 1 && max == SMALL_PATHS));
    let too_many_privileges = parse_permissions(permissions(&[("/a", four)]).as_slice(), &limits);
    assert!(matches!(
        too_many_privileges,
        Err(ParseError::TooManyPrivileges { count, max }) if count == SMALL_PRIVILEGES + 1 && max == SMALL_PRIVILEGES
    ));
    let too_many_grants = parse_permissions(permissions(&[("/a", three), ("/b", three)]).as_slice(), &limits);
    assert!(matches!(
        too_many_grants,
        Err(ParseError::TooManyGrants { count, max }) if count == GRANTS_SEEN && max == SMALL_GRANTS
    ));
    [
        ParseError::TooManyItems { count: 1, max: 0 },
        ParseError::TooManyPrivileges { count: 1, max: 0 },
        ParseError::TooManyGrants { count: 1, max: 0 },
    ]
    .iter()
    .for_each(|error| assert!(error.to_string().contains("limit")));
    Ok(())
}


#[test]
fn a_hundred_thousand_paths_and_ten_thousand_privileges_are_refused() -> TestResult {
    let limits = Limits::default();
    let paths = (0..HUGE_PATHS).map(|index| format!(r#""/p{index}":{{}}"#)).collect::<Vec<_>>().join(",");
    assert!(matches!(
        parse_permissions(format!(r#"{{"data":{{{paths}}}}}"#).as_bytes(), &limits),
        Err(ParseError::TooManyItems { count, .. }) if count == HUGE_PATHS
    ));
    let privileges = (0..HUGE_PRIVILEGES)
        .map(|index| format!(r#""P.N{index}":1"#))
        .collect::<Vec<_>>()
        .join(",");
    assert!(matches!(
        parse_permissions(format!(r#"{{"data":{{"/":{{{privileges}}}}}}}"#).as_bytes(), &limits),
        Err(ParseError::TooManyPrivileges { count, .. }) if count == HUGE_PRIVILEGES
    ));
    Ok(())
}


#[test]
fn a_deeply_nested_permission_document_is_refused() -> TestResult {
    let nested = format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH));
    let limits = Limits::default();
    assert!(matches!(
        parse_permissions(format!(r#"{{"data":{{"/":{{"VM.Audit":{nested}}}}}}}"#).as_bytes(), &limits),
        Err(ParseError::Malformed { .. })
    ));
    assert!(matches!(
        parse_permissions(format!(r#"{{"data":{nested}}}"#).as_bytes(), &limits),
        Err(ParseError::Malformed { .. })
    ));
    Ok(())
}


#[test]
fn an_empty_map_parses_to_no_paths() -> TestResult {
    assert_eq!(
        parse_permissions(br#"{"data":{}}"#.as_slice(), &Limits::default())?,
        Permissions::default()
    );
    Ok(())
}
