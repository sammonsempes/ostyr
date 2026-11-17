use crate::common::types::TestResult;
use connector_manifest::cli::run;
use connector_manifest::error::ConnectorError;
use connector_manifest::model::{
    MAX_ACTIONS, MAX_OPENAPI_BYTES, MAX_OPENAPI_OPERATIONS, MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES, MAX_OPENAPI_SERVERS,
    MAX_URL_BYTES,
};
use connector_manifest::openapi::{openapi_error, parse_document};
use connector_manifest::output::{
    create_package, create_package_with, open_parent, remove_package, split_target, write_skeleton, write_skeleton_with, write_staged_with,
};
use connector_manifest::skeleton::{build_skeleton, fallback_shape, skeleton_from_file, valid_path, valid_url, Skeleton};
use connector_manifest::verify::write_all_bytes;
use rustix::fs::OFlags;
use rustix::io::Errno;
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tempfile::TempDir;


const MIB: usize = 1_048_576;


const LARGE_VALUE_BYTES: usize = 7 * MIB;


const PETSTORE_OPERATION_COUNT: usize = 3;


const BAD_ID_COUNT: usize = 3;


const ID_OPERATION_COUNT: usize = 4;


const BAD_PATH_COUNT: usize = 5;


const BAD_PARAMETER_COUNT: usize = 5;


const BAD_SERVER_COUNT: usize = 3;


const BAD_SCHEME_COUNT: usize = 4;


const PACKAGE_FILE_COUNT: usize = 2;


const DEEP_NESTING: usize = 10_000;


const OPERATION_PATHS_OVER_CAP: usize = 513;


const OWNER_ONLY_MODE: u32 = 0o700;


const MODE_MASK: u32 = 0o777;


const SPOOF_OPERATION_COUNT: usize = 2;


const MARKER: &str = "VENDORMARKER";


const PETSTORE: &str = r#"{
  "openapi": "3.0.3",
  "info": {"title": "Petstore", "version": "1"},
  "servers": [{"url": "https://petstore.example.com/v1"}],
  "paths": {
    "/pets": {
      "get": {"operationId": "listPets", "parameters": [{"name": "limit", "in": "query"}]},
      "post": {"operationId": "createPets"}
    },
    "/pets/{petId}": {
      "parameters": [{"name": "petId", "in": "path"}],
      "get": {"operationId": "showPetById"}
    }
  },
  "components": {"securitySchemes": {"ApiKey": {"type": "apiKey"}}}
}"#;


const PETSTORE_MANIFEST: &str = "name: 'petstore'
version: 0.1.0
publisher: 'acme'
rights: []
actions:
  - name: 'listpets'
    targets: [api:read]
    default_approval: human
  - name: 'createpets'
    targets: [api:write]
    default_approval: human
  - name: 'showpetbyid'
    targets: [api:read]
    default_approval: human
config:
  - name: 'base_url'
    kind: string
    required: true
  - name: 'secret_apikey'
    kind: secret_file
    required: true
";


const PETSTORE_OPERATIONS: &str = "servers:
  - \"https://petstore.example.com/v1\"
operations:
  - method: get
    path: \"/pets\"
    operation: 'listpets'
    parameters:
      - name: 'limit'
        in: query
  - method: post
    path: \"/pets\"
    operation: 'createpets'
    parameters: []
  - method: get
    path: \"/pets/{petId}\"
    operation: 'showpetbyid'
    parameters:
      - name: 'pet_id'
        in: path
";


fn generate(text: &str) -> Result<Skeleton, ConnectorError> {
    build_skeleton(&parse_document(text.as_bytes())?, "petstore", "acme")
}


fn document(paths: &str, extra: &str) -> String {
    format!("{{\"openapi\":\"3.1.0\",\"paths\":{{{paths}}}{extra}}}")
}


fn failing_writer(_file: &mut fs::File, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::other("write interrupted"))
}


fn many_paths(count: usize) -> String {
    (0..count).map(|index| format!("\"/p{index}\":{{}}")).collect::<Vec<_>>().join(",")
}


fn many_parameters(count: usize) -> String {
    (0..count).map(|_| "{\"name\":\"a\",\"in\":\"query\"}").collect::<Vec<_>>().join(",")
}


fn bound_of(result: Result<Skeleton, ConnectorError>) -> Option<(&'static str, usize)> {
    match result {
        Err(ConnectorError::OpenApiBound { bound, max }) => Some((bound, max)),
        _ => None,
    }
}


#[test]
fn a_petstore_document_gives_the_exact_draft_package() -> TestResult {
    let skeleton = generate(PETSTORE)?;
    assert_eq!(skeleton.manifest, PETSTORE_MANIFEST);
    assert_eq!(skeleton.operations, PETSTORE_OPERATIONS);
    assert_eq!(skeleton.summary.operations, PETSTORE_OPERATION_COUNT);
    assert_eq!(skeleton.summary.bad_path + skeleton.summary.bad_scheme + skeleton.summary.bad_server, 0);
    Ok(())
}


#[test]
fn an_empty_document_gives_empty_lists() -> TestResult {
    let skeleton = generate("{\"openapi\":\"3.0.0\"}")?;
    assert!(skeleton.manifest.contains("actions: []\n"));
    assert!(skeleton.operations.starts_with("servers: []\noperations: []\n"));
    Ok(())
}


#[test]
fn the_path_count_is_bounded_and_the_entry_after_the_cap_is_never_built() -> TestResult {
    assert!(generate(&document(&many_paths(MAX_OPENAPI_PATHS), ""))?.summary.operations == 0);
    let over = format!("{},\"/bad\":5", many_paths(MAX_OPENAPI_PATHS + 1));
    assert_eq!(bound_of(generate(&document(&over, ""))), Some(("paths", MAX_OPENAPI_PATHS)));
    let broken = format!("{},\"/bad\":@", many_paths(MAX_OPENAPI_PATHS + 1));
    assert!(matches!(generate(&document(&broken, "")), Err(ConnectorError::OpenApi { .. })));
    Ok(())
}


#[test]
fn a_path_level_parameter_list_over_its_bound_skips_that_item_alone() -> TestResult {
    let at_cap = format!("\"/a\":{{\"parameters\":[{}],\"get\":{{}}}}", many_parameters(MAX_OPENAPI_PARAMETERS));
    assert_eq!(generate(&document(&at_cap, ""))?.summary.operations, 1);
    let over = format!(
        "\"/a\":{{\"parameters\":[{},5],\"get\":{{}}}},\"/b\":{{\"put\":{{}}}}",
        many_parameters(MAX_OPENAPI_PARAMETERS + 1)
    );
    let skeleton = generate(&document(&over, ""))?;
    assert_eq!(skeleton.summary.bad_path_item, 1);
    assert_eq!(skeleton.summary.operations, 1);
    Ok(())
}


#[test]
fn an_operation_over_its_parameter_bound_is_skipped_alone() -> TestResult {
    let at_cap = format!("\"/a\":{{\"get\":{{\"parameters\":[{}]}}}}", many_parameters(MAX_OPENAPI_PARAMETERS));
    assert_eq!(generate(&document(&at_cap, ""))?.summary.operations, 1);
    let over = format!(
        "\"/a\":{{\"get\":{{\"parameters\":[{},5]}},\"put\":{{}}}}",
        many_parameters(MAX_OPENAPI_PARAMETERS + 1)
    );
    let skeleton = generate(&document(&over, ""))?;
    assert_eq!(skeleton.summary.bad_operation, 1);
    assert_eq!(skeleton.summary.operations, 1);
    Ok(())
}


#[test]
fn the_security_scheme_count_is_bounded() -> TestResult {
    let schemes = |count: usize, tail: &str| {
        let list = (0..count)
            .map(|index| format!("\"s{index}\":{{\"type\":\"http\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        document("", &format!(",\"components\":{{\"securitySchemes\":{{{list}{tail}}}}}"))
    };
    assert!(generate(&schemes(MAX_OPENAPI_SCHEMES, ""))?.manifest.contains("secret_s0"));
    assert_eq!(
        bound_of(generate(&schemes(MAX_OPENAPI_SCHEMES + 1, ",\"x\":5"))),
        Some(("security schemes", MAX_OPENAPI_SCHEMES))
    );
    Ok(())
}


#[test]
fn the_server_count_is_bounded() -> TestResult {
    let servers = |count: usize, tail: &str| {
        let list = (0..count).map(|_| "{\"url\":\"https://a.example\"}").collect::<Vec<_>>().join(",");
        document("", &format!(",\"servers\":[{list}{tail}]"))
    };
    assert!(generate(&servers(MAX_OPENAPI_SERVERS, ""))?.operations.contains("https://a.example"));
    assert_eq!(
        bound_of(generate(&servers(MAX_OPENAPI_SERVERS + 1, ",5"))),
        Some(("servers", MAX_OPENAPI_SERVERS))
    );
    assert!(matches!(
        generate(&servers(MAX_OPENAPI_SERVERS + 1, ",@")),
        Err(ConnectorError::OpenApi { .. })
    ));
    assert!(matches!(generate(&document("", ",\"servers\":[@]")), Err(ConnectorError::OpenApi { .. })));
    Ok(())
}


#[test]
fn the_total_operation_count_and_the_action_cap_name_their_bound() -> TestResult {
    let many_operations = |count: usize| {
        let list = (0..count)
            .map(|index| format!("\"/p{index}\":{{\"get\":{{}},\"put\":{{}},\"post\":{{}},\"delete\":{{}},\"head\":{{}},\"patch\":{{}},\"trace\":{{}},\"options\":{{}}}}"))
            .collect::<Vec<_>>()
            .join(",");
        document(&list, "")
    };
    assert_eq!(
        bound_of(generate(&many_operations(OPERATION_PATHS_OVER_CAP))),
        Some(("operations", MAX_OPENAPI_OPERATIONS))
    );
    let over_actions = (0..=MAX_ACTIONS)
        .map(|index| format!("\"/p{index}\":{{\"get\":{{}}}}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(bound_of(generate(&document(&over_actions, ""))), Some(("actions", MAX_ACTIONS)));
    Ok(())
}


#[test]
fn large_ignored_values_are_accepted_and_a_larger_document_is_refused_before_parsing() -> TestResult {
    let seven = "x".repeat(LARGE_VALUE_BYTES);
    let ignored = format!(",\"x-extension\":\"{seven}\",\"info\":{{\"description\":\"{seven}\"}}");
    assert!(generate(&document("", &ignored)).is_ok());
    let directory = TempDir::new()?;
    let file = directory.path().join("big.json");
    let mut text = vec![b' '; usize::try_from(MAX_OPENAPI_BYTES)? + 1];
    fs::write(&file, &text)?;
    assert!(matches!(
        skeleton_from_file(&file, "petstore", "acme"),
        Err(ConnectorError::FileTooLarge { max, .. }) if max == MAX_OPENAPI_BYTES
    ));
    text.truncate(usize::try_from(MAX_OPENAPI_BYTES)?);
    fs::write(&file, &text)?;
    assert!(matches!(
        skeleton_from_file(&file, "petstore", "acme"),
        Err(ConnectorError::OpenApi { .. })
    ));
    Ok(())
}


#[test]
fn a_missing_input_file_is_an_io_error() -> TestResult {
    let directory = TempDir::new()?;
    assert!(matches!(
        skeleton_from_file(&directory.path().join("none.json"), "petstore", "acme"),
        Err(ConnectorError::Io { .. })
    ));
    Ok(())
}


#[test]
fn a_bad_operation_id_is_skipped_alone_and_counted() -> TestResult {
    let paths = "\"/a\":{\"get\":{\"operationId\":\"has space\"},\"put\":{\"operationId\":\"caf\u{e9}\"},\"post\":{\"operationId\":\"-lead\"},\
                 \"delete\":{\"operationId\":\"ok.id\"}}";
    let skeleton = generate(&document(paths, ""))?;
    assert_eq!(skeleton.summary.bad_operation_id, BAD_ID_COUNT);
    assert_eq!(skeleton.summary.operations, ID_OPERATION_COUNT);
    assert!(skeleton.manifest.contains("name: 'ok.id'\n"));
    assert!(skeleton.manifest.contains("name: 'get_2'\n"));
    Ok(())
}


#[test]
fn colliding_missing_and_generated_shaped_ids_get_a_generated_name() -> TestResult {
    let paths = "\"/a\":{\"get\":{\"operationId\":\"Same\"},\"post\":{\"operationId\":\"SAME\"},\"put\":{},\"delete\":{\"operationId\":\"get_1\"}}";
    let skeleton = generate(&document(paths, ""))?;
    assert!(skeleton.manifest.contains("name: 'delete_1'\n"));
    assert!(skeleton.manifest.contains("name: 'same'\n"));
    assert!(skeleton.manifest.contains("name: 'post_3'\n"));
    assert!(skeleton.manifest.contains("name: 'put_4'\n"));
    assert!(fallback_shape("get_12"));
    assert!(!fallback_shape("get_"));
    assert!(!fallback_shape("get_1x"));
    assert!(!fallback_shape("other_1"));
    assert!(!fallback_shape("plain"));
    Ok(())
}


#[test]
fn bad_paths_are_skipped_alone_and_counted() -> TestResult {
    let paths = "\"/ok\":{\"get\":{}},\"/a/../b\":{\"get\":{},\"put\":{}},\"/q\\\"x\":{\"get\":{}},\"nolead\":{\"get\":{}},\"/./x\":{\"get\":{}}";
    let skeleton = generate(&document(paths, ""))?;
    assert_eq!(skeleton.summary.bad_path, BAD_PATH_COUNT);
    assert_eq!(skeleton.summary.operations, 1);
    assert!(valid_path("/a/{b}/c.d_e~f-g"));
    assert!(!valid_path(&format!("/{}", "a".repeat(MAX_URL_BYTES))));
    assert!(!valid_path("/caf\u{e9}"));
    Ok(())
}


#[test]
fn bad_parameters_are_skipped_and_counted() -> TestResult {
    let parameters = "[{\"name\":\"caf\u{e9}\",\"in\":\"query\"},{\"name\":\"ok\",\"in\":\"body\"},{\"$ref\":\"#/x\"},{\"name\":\"ok\"},\
                      {\"name\":\"ok\",\"in\":\"query\"},{\"name\":\"ok\",\"in\":\"query\"}]";
    let skeleton = generate(&document(&format!("\"/a\":{{\"get\":{{\"parameters\":{parameters}}}}}"), ""))?;
    assert_eq!(skeleton.summary.bad_parameter, BAD_PARAMETER_COUNT);
    assert_eq!(skeleton.operations.matches("- name: 'ok'").count(), 1);
    Ok(())
}


#[test]
fn servers_and_schemes_that_fail_their_grammar_are_counted() -> TestResult {
    let servers = ",\"servers\":[{\"url\":\"javascript:alert(1)\"},{\"url\":\"https://a.example/\\u0001\"},{},{\"url\":\"http://ok.example\"}]";
    let schemes = ",\"components\":{\"securitySchemes\":{\"Bad Name\":{\"type\":\"http\"},\"o\":{\"type\":\"oauth2\"},\"A\":{\"type\":\"http\"},\
                   \"a\":{\"type\":\"apiKey\"},\"n\":{}}}";
    let skeleton = generate(&document("", &format!("{servers}{schemes}")))?;
    assert_eq!(skeleton.summary.bad_server, BAD_SERVER_COUNT);
    assert_eq!(skeleton.summary.bad_scheme, BAD_SCHEME_COUNT);
    assert!(skeleton.operations.contains("http://ok.example"));
    assert!(!skeleton.operations.contains("javascript"));
    assert!(valid_url("https://a.example"));
    assert!(!valid_url("ftp://a.example"));
    assert!(!valid_url(&format!("https://{}", "a".repeat(MAX_URL_BYTES))));
    Ok(())
}


#[test]
fn the_names_given_on_the_command_line_follow_the_manifest_grammar() -> TestResult {
    let parsed = parse_document(PETSTORE.as_bytes())?;
    assert!(matches!(
        build_skeleton(&parsed, "Bad", "acme"),
        Err(ConnectorError::Invalid { field: "name" })
    ));
    assert!(matches!(
        build_skeleton(&parsed, "ok", "a\nrights: x"),
        Err(ConnectorError::Invalid { field: "publisher" })
    ));
    Ok(())
}


#[test]
fn a_document_error_carries_no_byte_of_the_document() -> TestResult {
    let wrong_type = format!("{{\"openapi\":\"3.0.0\",\"paths\":\"{MARKER}\"}}");
    let syntax = format!("{{\"openapi\":\"3.0.0\" {MARKER}}}");
    let truncated = format!("{{\"openapi\":\"{MARKER}");
    let nested = format!("{}{}", "[".repeat(DEEP_NESTING), "]".repeat(DEEP_NESTING));
    for text in [wrong_type, syntax, truncated, nested] {
        let error = parse_document(text.as_bytes()).err().ok_or("accepted")?;
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains(MARKER), "{shown}");
        assert!(matches!(error, ConnectorError::OpenApi { .. }));
        let source = Error::source(&error);
        assert!(source.is_none());
    }
    let wrong_version = parse_document(format!("{{\"openapi\":\"2.0\",\"x\":\"{MARKER}\"}}").as_bytes())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(wrong_version, ConnectorError::Invalid { field: "openapi" }));
    assert!(matches!(parse_document(b"{}"), Err(ConnectorError::Invalid { field: "openapi" })));
    Ok(())
}


#[test]
fn a_parser_error_without_a_bound_message_is_a_category_error() -> TestResult {
    let error = serde_json::from_str::<serde_json::Value>("{").err().ok_or("accepted")?;
    assert!(matches!(openapi_error(&error), ConnectorError::OpenApi { .. }));
    Ok(())
}


#[test]
fn the_output_directory_is_created_0700_with_both_files() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    write_skeleton(&target, &generate(PETSTORE)?)?;
    assert_eq!(fs::metadata(&target)?.permissions().mode() & MODE_MASK, OWNER_ONLY_MODE);
    assert_eq!(fs::read_to_string(target.join("connector.yaml"))?, PETSTORE_MANIFEST);
    assert_eq!(fs::read_to_string(target.join("operations.yaml"))?, PETSTORE_OPERATIONS);
    assert_eq!(fs::read_dir(&target)?.count(), PACKAGE_FILE_COUNT);
    Ok(())
}


#[test]
fn an_existing_directory_or_symlink_is_refused_and_nothing_is_written() -> TestResult {
    let parent = TempDir::new()?;
    let existing = parent.path().join("existing");
    fs::create_dir(&existing)?;
    assert!(matches!(write_skeleton(&existing, &generate(PETSTORE)?), Err(ConnectorError::Io { .. })));
    assert_eq!(fs::read_dir(&existing)?.count(), 0);
    let elsewhere = parent.path().join("elsewhere");
    fs::create_dir(&elsewhere)?;
    let link = parent.path().join("link");
    symlink(&elsewhere, &link)?;
    assert!(matches!(write_skeleton(&link, &generate(PETSTORE)?), Err(ConnectorError::Io { .. })));
    assert_eq!(fs::read_dir(&elsewhere)?.count(), 0);
    let dangling = parent.path().join("dangling");
    symlink(parent.path().join("nowhere"), &dangling)?;
    assert!(matches!(write_skeleton(&dangling, &generate(PETSTORE)?), Err(ConnectorError::Io { .. })));
    assert!(!parent.path().join("nowhere").exists());
    Ok(())
}


#[test]
fn a_failing_write_is_an_io_error() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    assert!(matches!(
        write_skeleton_with(failing_writer, &target, &generate(PETSTORE)?),
        Err(ConnectorError::Io { .. })
    ));
    Ok(())
}


#[test]
fn an_untrusted_or_missing_parent_and_a_nameless_target_are_refused() -> TestResult {
    let parent = TempDir::new()?;
    let skeleton = generate(PETSTORE)?;
    assert!(matches!(
        write_skeleton(&parent.path().join("missing").join("package"), &skeleton),
        Err(ConnectorError::WorkDir(_))
    ));
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(MODE_MASK))?;
    assert!(matches!(
        write_skeleton(&parent.path().join("package"), &skeleton),
        Err(ConnectorError::WorkDir(_))
    ));
    assert!(!parent.path().join("package").exists());
    assert!(matches!(
        write_skeleton(Path::new("/"), &skeleton),
        Err(ConnectorError::Invalid { field: "out-dir" })
    ));
    assert!(matches!(
        write_skeleton(&parent.path().join(".."), &skeleton),
        Err(ConnectorError::Invalid { field: "out-dir" })
    ));
    let raw_name = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff"));
    assert!(matches!(split_target(raw_name, "x"), Err(ConnectorError::Invalid { field: "out-dir" })));
    Ok(())
}


#[test]
fn the_command_line_writes_the_package_and_reports_the_counts_only() -> TestResult {
    let parent = TempDir::new()?;
    let input = parent.path().join("openapi.json");
    fs::write(&input, PETSTORE)?;
    let target = parent.path().join("package");
    let mut out = Vec::new();
    run(
        &[
            "skeleton",
            &input.display().to_string(),
            "petstore",
            "acme",
            &target.display().to_string(),
        ],
        0,
        &mut out,
    )?;
    assert_eq!(
        String::from_utf8(out)?,
        "skeleton operations=3 bad_path=0 bad_path_item=0 bad_operation=0 bad_operation_id=0 bad_parameter=0 bad_server=0 bad_scheme=0\n"
    );
    assert!(target.join("connector.yaml").is_file());
    Ok(())
}


const WRONG_TYPES: [&str; 6] = ["\"text\"", "5", "-5", "1.5", "true", "null"];


const BAD_ITEM_COUNT: usize = 2;


const NORMALISED_BAD_COUNT: usize = 3;


#[test]
fn a_path_item_or_operation_of_the_wrong_type_is_skipped_alone_and_counted() -> TestResult {
    for wrong in WRONG_TYPES {
        let paths = format!("\"/a\":{wrong},\"/b\":[1,{{\"x\":2}}],\"/c\":{{\"put\":[1],\"post\":{{\"operationId\":\"ok\"}}}}");
        let skeleton = generate(&document(&paths, ""))?;
        assert_eq!(skeleton.summary.bad_path_item, BAD_ITEM_COUNT);
        assert_eq!(skeleton.summary.bad_operation, 1);
        assert_eq!(skeleton.summary.operations, 1);
        assert!(skeleton.manifest.contains("name: 'ok'\n"));
    }
    let typed_id = generate(&document("\"/a\":{\"get\":{\"operationId\":5},\"put\":{}}", ""))?;
    assert_eq!(typed_id.summary.bad_operation, 1);
    assert_eq!(typed_id.summary.operations, 1);
    let mixed = "\"/a\":{\"parameters\":[5,{\"name\":\"x\",\"in\":\"query\"}],\"get\":{\"parameters\":\"no\"},\"put\":{}}";
    let mixed_skeleton = generate(&document(mixed, ""))?;
    assert_eq!(mixed_skeleton.summary.bad_parameter, 1);
    assert_eq!(mixed_skeleton.summary.bad_operation, 1);
    assert_eq!(mixed_skeleton.summary.operations, 1);
    let lists = generate(&document(
        "\"/a\":{\"get\":{\"parameters\":[\"x\",7]},\"summary\":5,\"x-y\":{},\"$ref\":\"z\"}",
        "",
    ))?;
    assert_eq!(lists.summary.bad_parameter, BAD_ITEM_COUNT);
    Ok(())
}


#[test]
fn a_wrong_typed_element_never_shows_its_bytes() -> TestResult {
    let paths = format!("\"/a\":{{\"get\":\"{MARKER}\",\"put\":{{\"operationId\":\"{MARKER}\"}}}},\"/b\":\"{MARKER}\"");
    let skeleton = generate(&document(&paths, ""))?;
    let shown = format!("{} {} {:?}", skeleton.manifest, skeleton.operations, skeleton.summary);
    assert!(!shown.contains(MARKER));
    Ok(())
}


#[test]
fn parameter_names_are_normalised_and_duplicates_dropped() -> TestResult {
    let parameters = "[{\"name\":\"petId\",\"in\":\"path\"},{\"name\":\"pet_id\",\"in\":\"query\"},{\"name\":\"X-Api-Key\",\"in\":\"header\"},\
                      {\"name\":\"userID\",\"in\":\"query\"},{\"name\":\"-lead\",\"in\":\"query\"},{\"name\":\"caf\u{e9}Id\",\"in\":\"query\"}]";
    let skeleton = generate(&document(&format!("\"/a\":{{\"get\":{{\"parameters\":{parameters}}}}}"), ""))?;
    assert_eq!(skeleton.summary.bad_parameter, NORMALISED_BAD_COUNT);
    for name in ["pet_id", "x_api_key", "user_id"] {
        assert_eq!(skeleton.operations.matches(&format!("- name: '{name}'\n")).count(), 1, "{name}");
    }
    assert!(skeleton.operations.contains("- name: 'pet_id'\n        in: path"));
    Ok(())
}


#[test]
fn a_failure_after_the_directory_exists_leaves_nothing_behind() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    assert!(write_skeleton_with(failing_writer, &target, &generate(PETSTORE)?).is_err());
    assert!(!target.exists());
    assert_eq!(fs::read_dir(parent.path())?.count(), 0);
    Ok(())
}


static REMOVE_TARGET: OnceLock<PathBuf> = OnceLock::new();


fn vanishing_writer(_file: &mut fs::File, _bytes: &[u8]) -> io::Result<()> {
    let directory = REMOVE_TARGET.get().ok_or_else(|| io::Error::other("unset"))?;
    fs::remove_dir_all(directory)?;
    Err(io::Error::other("write interrupted"))
}


#[test]
fn a_failed_cleanup_is_logged_and_does_not_panic() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    REMOVE_TARGET.set(target.clone()).map_err(|_| "already set")?;
    assert!(write_skeleton_with(vanishing_writer, &target, &generate(PETSTORE)?).is_err());
    assert!(!target.exists());
    Ok(())
}


#[test]
fn an_unreadable_entry_inside_the_cap_is_a_category_error() -> TestResult {
    let syntax = generate(&document("\"/a\":@", ""));
    assert!(matches!(syntax, Err(ConnectorError::OpenApi { .. })));
    let scheme = generate(&document("", ",\"components\":{\"securitySchemes\":{\"x\":5,\"y\":@}}"));
    assert!(matches!(scheme, Err(ConnectorError::OpenApi { .. })));
    Ok(())
}


static BLOCK_TARGET: OnceLock<PathBuf> = OnceLock::new();


fn blocking_writer(_file: &mut fs::File, _bytes: &[u8]) -> io::Result<()> {
    let directory = BLOCK_TARGET.get().ok_or_else(|| io::Error::other("unset"))?;
    fs::create_dir(directory.join("connector.yaml"))
}


#[test]
fn a_cleanup_that_cannot_remove_everything_is_logged_and_the_error_is_the_write() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    BLOCK_TARGET.set(target.clone()).map_err(|_| "already set")?;
    assert!(matches!(
        write_skeleton_with(blocking_writer, &target, &generate(PETSTORE)?),
        Err(ConnectorError::Io { .. })
    ));
    assert!(target.join("connector.yaml").is_dir());
    Ok(())
}


#[derive(Deserialize)]
struct ParameterEntry {
    name: String,
}


#[derive(Deserialize)]
struct OperationEntry {
    operation: String,
    parameters: Vec<ParameterEntry>,
}


#[derive(Deserialize)]
struct OperationsFile {
    operations: Vec<OperationEntry>,
}


const YAML_LOOKALIKES: [&str; 10] = ["null", "Null", "NULL", "true", "no", "123", "0x1f", "1e3", "2026-01-01", "inf"];


#[test]
fn names_that_read_as_other_yaml_types_stay_text() -> TestResult {
    for (index, name) in YAML_LOOKALIKES.iter().enumerate() {
        let paths = format!("\"/a\":{{\"get\":{{\"operationId\":\"{name}\",\"parameters\":[{{\"name\":\"{name}\",\"in\":\"query\"}}]}}}}");
        let schemes = format!(",\"components\":{{\"securitySchemes\":{{\"{name}\":{{\"type\":\"http\"}}}}}}");
        let skeleton = generate(&document(&paths, &schemes))?;
        let lower = name.to_ascii_lowercase();
        assert_eq!(skeleton.summary.operations, 1, "{index}");
        assert!(skeleton.manifest.contains(&format!("- name: '{lower}'\n")), "{name}");
        assert!(skeleton.manifest.contains(&format!("- name: 'secret_{lower}'\n")), "{name}");
        assert!(skeleton.operations.contains(&format!("operation: '{lower}'\n")), "{name}");
        let parameter = lower.replace('-', "_");
        assert!(skeleton.operations.contains(&format!("- name: '{parameter}'\n")), "{name}");
        let parsed = connector_manifest::manifest::parse_manifest(skeleton.manifest.as_bytes())?;
        assert_eq!(parsed.actions.first().map(|action| action.name.as_str()), Some(lower.as_str()));
        let reparsed: OperationsFile = serde_saphyr::from_str(&skeleton.operations)?;
        assert!(reparsed.operations.iter().all(|entry| entry.operation == lower));
        assert!(reparsed
            .operations
            .iter()
            .flat_map(|entry| entry.parameters.iter())
            .all(|entry| entry.name == parameter));
    }
    Ok(())
}


#[test]
fn an_element_that_repeats_a_bound_message_is_skipped_alone_not_taken_for_a_bound() -> TestResult {
    let paths = "\"/a\":{\"get\":\"too many paths\",\"put\":{\"parameters\":[\"too many servers\"]}},\"/b\":\"too many parameters\",\
                 \"/c\":{\"post\":{}}";
    let skeleton = generate(&document(paths, ""))?;
    assert_eq!(skeleton.summary.bad_path_item, 1);
    assert_eq!(skeleton.summary.bad_operation, 1);
    assert_eq!(skeleton.summary.bad_parameter, 1);
    assert_eq!(skeleton.summary.operations, SPOOF_OPERATION_COUNT);
    let top = generate(&document("", ",\"servers\":[\"too many servers\"]"))?;
    assert_eq!(top.summary.bad_server, 1);
    Ok(())
}


#[test]
fn an_operation_level_parameter_overrides_the_path_level_one() -> TestResult {
    let paths = "\"/a/{id}\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\"},{\"name\":\"q\",\"in\":\"query\"}],\
                 \"get\":{\"parameters\":[{\"name\":\"id\",\"in\":\"header\"}]}}";
    let skeleton = generate(&document(paths, ""))?;
    assert_eq!(skeleton.summary.bad_parameter, 1);
    assert!(skeleton.operations.contains("- name: 'id'\n        in: header"));
    assert!(!skeleton.operations.contains("in: path"));
    Ok(())
}


#[test]
fn a_generated_shaped_id_is_counted_and_a_userinfo_url_is_refused() -> TestResult {
    let skeleton = generate(&document("\"/a\":{\"get\":{\"operationId\":\"post_7\"}}", ""))?;
    assert_eq!(skeleton.summary.bad_operation_id, 1);
    assert!(!valid_url("https://user:pass@a.example"));
    assert!(!valid_url("https://a.example@evil.example"));
    Ok(())
}


#[test]
fn a_wrong_typed_server_or_scheme_is_skipped_alone_and_counted() -> TestResult {
    let servers = ",\"servers\":[\"x\",{\"url\":\"https://ok.example\"}]";
    let schemes = ",\"components\":{\"securitySchemes\":{\"a\":\"x\",\"b\":{\"type\":\"http\"}}}";
    let skeleton = generate(&document("", &format!("{servers}{schemes}")))?;
    assert_eq!(skeleton.summary.bad_server, 1);
    assert_eq!(skeleton.summary.bad_scheme, 1);
    assert!(skeleton.operations.contains("https://ok.example"));
    assert!(skeleton.manifest.contains("secret_b"));
    Ok(())
}


#[test]
fn a_duplicate_valid_server_is_collapsed_and_not_counted() -> TestResult {
    let servers = ",\"servers\":[{\"url\":\"https://a.example\"},{\"url\":\"https://a.example\"},{\"url\":\"ftp://b.example\"}]";
    let skeleton = generate(&document("", servers))?;
    assert_eq!(skeleton.summary.bad_server, 1);
    assert_eq!(skeleton.operations.matches("https://a.example").count(), 1);
    Ok(())
}


fn refusing_opener(_parent: BorrowedFd<'_>, _name: &str, _flags: OFlags) -> Result<OwnedFd, Errno> {
    Err(Errno::IO)
}


#[test]
fn the_files_land_in_the_created_directory_even_if_its_name_is_swapped() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    let held = open_parent(parent.path())?;
    let package = create_package(held, "package".to_owned(), "package")?;
    fs::rename(&target, parent.path().join("moved"))?;
    fs::create_dir(&target)?;
    write_staged_with(write_all_bytes, &package, "connector.yaml", "text")?;
    assert_eq!(fs::read_to_string(parent.path().join("moved").join("connector.yaml"))?, "text");
    assert_eq!(fs::read_dir(&target)?.count(), 0);
    Ok(())
}


#[test]
fn a_directory_that_cannot_be_held_is_removed_again() -> TestResult {
    let parent = TempDir::new()?;
    let held = open_parent(parent.path())?;
    let result = create_package_with(refusing_opener, held, "package".to_owned(), "package");
    assert!(matches!(result, Err(ConnectorError::Io { .. })));
    assert_eq!(fs::read_dir(parent.path())?.count(), 0);
    Ok(())
}


fn other_directory_opener(parent: BorrowedFd<'_>, _name: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(parent, "other", flags, rustix::fs::Mode::empty())
}


fn file_opener(parent: BorrowedFd<'_>, _name: &str, _flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(parent, "other", OFlags::RDONLY | OFlags::CLOEXEC, rustix::fs::Mode::empty())
}


const OTHER_MODE: u32 = 0o755;


const PRIVATE_MODE: u32 = 0o700;


fn refused_with(opener: connector_manifest::types::OpenFn, prepare: fn(&Path) -> io::Result<()>) -> TestResult {
    let parent = TempDir::new()?;
    let other = parent.path().join("other");
    fs::create_dir(&other)?;
    fs::set_permissions(&other, fs::Permissions::from_mode(PRIVATE_MODE))?;
    prepare(&other)?;
    let held = open_parent(parent.path())?;
    let result = create_package_with(opener, held, "package".to_owned(), "package");
    assert!(matches!(result, Err(ConnectorError::Invalid { field: "out-dir" })));
    assert!(parent.path().join("package").is_dir());
    assert!(other.exists());
    Ok(())
}


fn add_file(path: &Path) -> io::Result<()> {
    fs::write(path.join("x"), "x")
}


fn widen(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(OTHER_MODE))
}


fn replace_with_file(path: &Path) -> io::Result<()> {
    fs::remove_dir(path)?;
    fs::write(path, "x")
}


#[test]
fn a_handle_that_is_not_the_new_empty_private_directory_is_refused() -> TestResult {
    refused_with(other_directory_opener, add_file)?;
    refused_with(other_directory_opener, widen)?;
    refused_with(file_opener, replace_with_file)?;
    Ok(())
}


#[test]
fn a_genuine_package_is_removed_through_its_own_name() -> TestResult {
    let parent = TempDir::new()?;
    let held = open_parent(parent.path())?;
    let package = create_package(held, "package".to_owned(), "package")?;
    assert!(remove_package(&package.parent, &package.directory, "package").is_empty());
    assert!(!parent.path().join("package").exists());
    Ok(())
}


#[test]
fn a_planted_empty_directory_survives_the_removal_of_the_moved_one() -> TestResult {
    let parent = TempDir::new()?;
    let target = parent.path().join("package");
    let held = open_parent(parent.path())?;
    let package = create_package(held, "package".to_owned(), "package")?;
    write_staged_with(write_all_bytes, &package, "connector.yaml", "text")?;
    fs::rename(&target, parent.path().join("moved"))?;
    fs::create_dir(&target)?;
    drop(package);
    assert!(target.is_dir());
    assert!(!parent.path().join("moved").join("connector.yaml").exists());
    assert!(parent.path().join("moved").is_dir());
    Ok(())
}


#[test]
fn a_directory_whose_name_is_gone_is_not_removed_and_not_reported() -> TestResult {
    let parent = TempDir::new()?;
    let held = open_parent(parent.path())?;
    let package = create_package(held, "package".to_owned(), "package")?;
    fs::rename(parent.path().join("package"), parent.path().join("moved"))?;
    assert!(remove_package(&package.parent, &package.directory, "package").is_empty());
    assert!(parent.path().join("moved").is_dir());
    Ok(())
}
