use crate::common::types::TestResult;
use connector_manifest::cli::run;
use connector_manifest::error::ConnectorError;
use connector_manifest::model::{
    MAX_ACTIONS, MAX_OPENAPI_BYTES, MAX_OPENAPI_OPERATIONS, MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES, MAX_OPENAPI_SERVERS,
    MAX_URL_BYTES,
};
use connector_manifest::openapi::{openapi_error, parse_document};
use connector_manifest::skeleton::{
    build_skeleton, create_directory, fallback_shape, skeleton_from_file, valid_path, valid_url, write_skeleton, write_skeleton_with,
    write_staged_with, Skeleton,
};
use connector_manifest::verify::write_all_bytes;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::TempDir;


const MIB: usize = 1_048_576;


const LARGE_VALUE_BYTES: usize = 7 * MIB;


const PETSTORE_OPERATION_COUNT: usize = 3;


const BAD_ID_COUNT: usize = 3;


const ID_OPERATION_COUNT: usize = 4;


const BAD_PATH_COUNT: usize = 5;


const BAD_PARAMETER_COUNT: usize = 4;


const BAD_SERVER_COUNT: usize = 3;


const BAD_SCHEME_COUNT: usize = 4;


const PACKAGE_FILE_COUNT: usize = 2;


const DEEP_NESTING: usize = 10_000;


const OPERATION_PATHS_OVER_CAP: usize = 513;


const OWNER_ONLY_MODE: u32 = 0o700;


const MODE_MASK: u32 = 0o777;


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
      "parameters": [{"name": "pet_id", "in": "path"}],
      "get": {"operationId": "showPetById"}
    }
  },
  "components": {"securitySchemes": {"ApiKey": {"type": "apiKey"}}}
}"#;


const PETSTORE_MANIFEST: &str = "name: petstore
version: 0.1.0
publisher: acme
rights: []
actions:
  - name: listpets
    targets: [api:read]
    default_approval: human
  - name: createpets
    targets: [api:write]
    default_approval: human
  - name: showpetbyid
    targets: [api:read]
    default_approval: human
config:
  - name: base_url
    kind: string
    required: true
  - name: secret_apikey
    kind: secret_file
    required: true
";


const PETSTORE_OPERATIONS: &str = "servers:
  - \"https://petstore.example.com/v1\"
operations:
  - method: get
    path: \"/pets\"
    operation: listpets
    parameters:
      - name: limit
        in: query
  - method: post
    path: \"/pets\"
    operation: createpets
    parameters: []
  - method: get
    path: \"/pets/{petId}\"
    operation: showpetbyid
    parameters:
      - name: pet_id
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
    Ok(())
}


#[test]
fn a_path_level_parameter_list_is_bounded() -> TestResult {
    let at_cap = format!("\"/a\":{{\"parameters\":[{}]}}", many_parameters(MAX_OPENAPI_PARAMETERS));
    assert!(generate(&document(&at_cap, "")).is_ok());
    let over = format!("\"/a\":{{\"parameters\":[{},5]}}", many_parameters(MAX_OPENAPI_PARAMETERS + 1));
    assert_eq!(bound_of(generate(&document(&over, ""))), Some(("parameters", MAX_OPENAPI_PARAMETERS)));
    Ok(())
}


#[test]
fn an_operation_level_parameter_list_is_bounded() -> TestResult {
    let at_cap = format!("\"/a\":{{\"get\":{{\"parameters\":[{}]}}}}", many_parameters(MAX_OPENAPI_PARAMETERS));
    assert!(generate(&document(&at_cap, "")).is_ok());
    let over = format!(
        "\"/a\":{{\"get\":{{\"parameters\":[{},5]}}}}",
        many_parameters(MAX_OPENAPI_PARAMETERS + 1)
    );
    assert_eq!(bound_of(generate(&document(&over, ""))), Some(("parameters", MAX_OPENAPI_PARAMETERS)));
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
    assert!(skeleton.manifest.contains("name: ok.id\n"));
    assert!(skeleton.manifest.contains("name: get_2\n"));
    Ok(())
}


#[test]
fn colliding_missing_and_generated_shaped_ids_get_a_generated_name() -> TestResult {
    let paths = "\"/a\":{\"get\":{\"operationId\":\"Same\"},\"post\":{\"operationId\":\"SAME\"},\"put\":{},\"delete\":{\"operationId\":\"get_1\"}}";
    let skeleton = generate(&document(paths, ""))?;
    assert!(skeleton.manifest.contains("name: delete_1\n"));
    assert!(skeleton.manifest.contains("name: same\n"));
    assert!(skeleton.manifest.contains("name: post_3\n"));
    assert!(skeleton.manifest.contains("name: put_4\n"));
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
    assert_eq!(skeleton.operations.matches("- name: ok").count(), 1);
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
    let key = format!("{{\"openapi\":\"3.0.0\",\"paths\":{{\"/a\":{{\"{MARKER}\":1,\"get\":\"{MARKER}\"}}}}}}");
    let nested = format!("{}{}", "[".repeat(DEEP_NESTING), "]".repeat(DEEP_NESTING));
    for text in [wrong_type, syntax, truncated, key, nested] {
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
    assert!(create_directory(&dangling).is_err());
    assert!(!parent.path().join("nowhere").exists());
    Ok(())
}


#[test]
fn a_failing_write_or_rename_is_an_io_error() -> TestResult {
    let parent = TempDir::new()?;
    let skeleton = generate(PETSTORE)?;
    let target = parent.path().join("package");
    assert!(matches!(
        write_skeleton_with(failing_writer, &target, &skeleton),
        Err(ConnectorError::Io { .. })
    ));
    let missing = parent.path().join("missing");
    assert!(matches!(
        write_staged_with(failing_writer, &missing, "connector.yaml", "x"),
        Err(ConnectorError::Io { .. })
    ));
    let blocked = parent.path().join("blocked");
    fs::create_dir_all(blocked.join("connector.yaml"))?;
    assert!(matches!(
        write_staged_with(write_all_bytes, &blocked, "connector.yaml", "x"),
        Err(ConnectorError::Io { .. })
    ));
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
        "skeleton operations=3 bad_path=0 bad_operation_id=0 bad_parameter=0 bad_server=0 bad_scheme=0\n"
    );
    assert!(target.join("connector.yaml").is_file());
    Ok(())
}
