use crate::types::TestResult;
use agent_linux::error::{OsqueryError, SensorError};
use agent_linux::model::{
    OsqueryEnv, OsquerySettings, DEFAULT_OSQUERY_DEADLINE_SECONDS, DEFAULT_OSQUERY_MEMORY_BYTES, DEFAULT_OSQUERY_TEMP_BYTES,
    DEFAULT_OSQUERY_TEMP_TOTAL_BYTES,
};
use agent_linux::model::{MOUNT_PATH, NSENTER_PATH, OSQUERYI_PATH, PRLIMIT_PATH, UMOUNT_PATH, UNSHARE_PATH};
use agent_linux::osquery::{
    check_program, check_query, errno_error, has_control, logger_dir_fault, osquery_error_of, prepare_logger_dir, program_fault, query_fault,
    query_spec, release_mounts, row_of, rows_from_output, rows_with_builder, run_query, tool_paths, umount_path, NamespaceGuard, FIXED_ARGUMENTS,
    LOGGER_DIR_NAME, MAX_COLUMNS, MAX_QUERY_BYTES, MAX_ROWS, MAX_ROW_BYTES, MAX_VALUE_BYTES, NAMESPACE_FILE_NAME, TEMP_DIR_NAME,
};
use agent_linux::types::UpdateFuture;
use serde_json::{json, Value};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};


const OWNER_ONLY_DIR: u32 = 0o700;


const OWNER_ONLY_FILE: u32 = 0o600;


const OPEN_DIR: u32 = 0o777;


const PROGRAM_MODE: u32 = 0o755;


const GROUP_WRITABLE_PROGRAM: u32 = 0o775;


const INVALID_BYTE: u8 = 0xff;


const MARKER: &str = "SECRET-MARKER-9f3a";


const EXIT_CODE: i32 = 2;


const SELF_BIND_CALL: usize = 2;


const MAKE_PRIVATE_CALL: usize = 3;


const CREATE_CALL: usize = 4;


const CREATE_STEP: usize = 2;


const TOOL_COUNT: usize = 6;


const RELEASE_CALLS_AFTER_TWO_DROPS: usize = 4;


const TARGET_COUNT: usize = 2;


const HEAD_WORDS: usize = 3;


const CALL_LOG: &str = "calls.log";


const TOOLS: [&str; TOOL_COUNT] = ["prlimit", "unshare", "nsenter", "mount", "umount", "osqueryi"];


const OVER_COLUMNS: usize = MAX_COLUMNS + 1;


const REGULAR_FILE_MODE: u32 = 0o100_644;


const DIRECTORY_MODE: u32 = 0o040_755;


const GROUP_WRITABLE_FILE_MODE: u32 = 0o100_664;


const OTHER_USER: u32 = 4_242;


const MODE_BITS: u32 = 0o777;


const RUN_CALLS: usize = 8;


const REFUSED_ROWS: usize = 8;


const KEPT_ROWS: usize = 4;


fn echo(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let mut row = serde_json::Map::new();
    row.insert("program".to_owned(), Value::String(spec.program.display().to_string()));
    row.insert("tmpdir".to_owned(), Value::String(format!("{:?}", spec.environment)));
    row.insert("deadline".to_owned(), Value::String(deadline.as_secs().to_string()));
    row.insert("max_output".to_owned(), Value::String(spec.max_output.to_string()));
    row.insert("environment".to_owned(), Value::String(format!("{:?}", spec.environment)));
    spec.arguments.iter().enumerate().for_each(|(index, argument)| {
        row.insert(format!("arg{index}"), Value::String(argument.to_string_lossy().into_owned()));
    });
    let body = serde_json::to_vec(&json!([row])).map_err(|_| SensorError::Parse);
    Box::pin(async move { body })
}


fn is_setup(spec: &agent_linux::model::CommandSpec) -> bool {
    spec.max_output != agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES
}


fn program_name(spec: &agent_linux::model::CommandSpec) -> String {
    spec.program
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}


fn log_call(spec: &agent_linux::model::CommandSpec) -> io::Result<()> {
    let directory = spec
        .arguments
        .iter()
        .filter_map(|argument| argument.to_str())
        .map(|argument| argument.trim_start_matches("--mount="))
        .find_map(|argument| argument.find(TEMP_DIR_NAME).and_then(|at| argument.get(..at + TEMP_DIR_NAME.len())));
    let log = directory.map(|path| Path::new(path).join(CALL_LOG));
    let words: Vec<String> = spec.arguments.iter().map(|argument| argument.to_string_lossy().into_owned()).collect();
    let line = format!("{} {}\n", program_name(spec), words.join(" "));
    log.map_or(Ok(()), |path| {
        fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(line.as_bytes())
    })
}


fn recording(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    let logged = log_call(&spec).map_err(SensorError::Io);
    Box::pin(async move { logged.map(|()| b"[]".to_vec()) })
}


fn unshare_fails(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let unshare = program_name(&spec) == "unshare";
    let outcome = recording(spec, deadline);
    if unshare {
        fail(SensorError::Exit(Some(1)))
    } else {
        outcome
    }
}


fn log_release(path: &Path) -> io::Result<()> {
    let directory = path.ancestors().find(|ancestor| ancestor.ends_with(TEMP_DIR_NAME));
    let line = format!("umount {}\n", path.display());
    directory.map_or(Ok(()), |found| {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(found.join(CALL_LOG))?
            .write_all(line.as_bytes())
    })
}


fn release_ok(path: &Path) -> io::Result<()> {
    log_release(path)
}


fn release_fails(path: &Path) -> io::Result<()> {
    log_release(path)?;
    Err(io::Error::other("not mounted"))
}


fn sqlite_full(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(Some(agent_linux::osquery::SQLITE_FULL_EXIT)))
    }
}


fn answer(body: Vec<u8>) -> UpdateFuture {
    Box::pin(async move { Ok(body) })
}


fn fail(error: SensorError) -> UpdateFuture {
    Box::pin(async move { Err(error) })
}


fn too_many_rows(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{}{{}}]", "{},".repeat(MAX_ROWS)).into_bytes())
    }
}


fn exactly_max_rows(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{}{{}}]", "{},".repeat(MAX_ROWS - 1)).into_bytes())
    }
}


fn timeout(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Timeout)
    }
}


fn too_large(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::TooLarge(1))
    }
}


fn exit_two(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(Some(EXIT_CODE)))
    }
}


fn killed(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(None))
    }
}


fn no_start(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Io(io::Error::from(io::ErrorKind::NotFound)))
    }
}


fn marked_garbage(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{{\"a\":\"x\"}}\n {MARKER} \u{1b}[31m").into_bytes())
    }
}


struct Fixture {
    _root: TempDir,
    state: PathBuf,
    settings: OsquerySettings,
    tools: Vec<PathBuf>,
}


fn make_dir(path: &Path, mode: u32) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}


fn program_of(fixture: &Fixture) -> Result<PathBuf, Box<dyn Error>> {
    Ok(fixture.tools.last().ok_or("no tools")?.clone())
}


fn trusted_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let root = tempdir()?;
    let bin = root.path().join("bin");
    make_dir(&bin, PROGRAM_MODE)?;
    let tools: Vec<PathBuf> = TOOLS.iter().map(|name| bin.join(name)).collect();
    tools.iter().try_for_each(|path| {
        fs::write(path, b"")?;
        fs::set_permissions(path, fs::Permissions::from_mode(PROGRAM_MODE))
    })?;
    let state = root.path().join("state");
    make_dir(&state, OWNER_ONLY_DIR)?;
    let settings = OsquerySettings::default();
    Ok(Fixture {
        _root: root,
        state,
        settings,
        tools,
    })
}


fn env_of(fixture: &Fixture, run: agent_linux::types::UpdateRunFn) -> OsqueryEnv {
    OsqueryEnv {
        state_dir: fixture.state.clone(),
        trusted_uid: trusted_uid(),
        run,
        release: release_ok,
        tools: fixture.tools.clone(),
    }
}


#[tokio::test]
async fn a_query_runs_with_separate_arguments_and_the_fixed_flags() -> TestResult {
    let fixture = fixture()?;
    let query = "SELECT name, version FROM deb_packages LIMIT 5; -- x";
    let result = run_query(&env_of(&fixture, echo), &fixture.settings, query).await?;
    assert_eq!((result.rows.len(), result.refused_rows), (1, 0));
    let row = result.rows.first().ok_or("no row")?;
    let ns_file = fixture.state.join(TEMP_DIR_NAME).join(NAMESPACE_FILE_NAME);
    let wrapper: [String; WRAPPER_ARGUMENTS] = [
        format!("--mount={}", ns_file.display()),
        format!("--wd={}", fixture.state.join(TEMP_DIR_NAME).display()),
        "--".to_owned(),
        PRLIMIT_PATH.to_owned(),
        format!("--as={DEFAULT_OSQUERY_MEMORY_BYTES}"),
        format!("--cpu={DEFAULT_OSQUERY_DEADLINE_SECONDS}"),
        format!("--fsize={DEFAULT_OSQUERY_TEMP_BYTES}"),
        "--core=1".to_owned(),
        "--".to_owned(),
        OSQUERYI_PATH.to_owned(),
    ];
    let first = wrapper.len();
    assert_eq!(row.get("program").cloned(), Some(NSENTER_PATH.to_owned()));
    wrapper
        .iter()
        .enumerate()
        .for_each(|(index, flag)| assert_eq!(row.get(&format!("arg{index}")), Some(flag)));
    FIXED_ARGUMENTS
        .iter()
        .enumerate()
        .for_each(|(index, flag)| assert_eq!(row.get(&format!("arg{}", first + index)).map(String::as_str), Some(*flag)));
    let logger = fixture.state.join(LOGGER_DIR_NAME);
    let logger_index = first + FIXED_ARGUMENTS.len();
    let last = logger_index + 1;
    assert_eq!(
        row.get(&format!("arg{logger_index}")).cloned(),
        Some(format!("--logger_path={}", logger.display()))
    );
    assert_eq!(row.get(&format!("arg{last}")).map(String::as_str), Some(query));
    assert!(row.get(&format!("arg{}", last + 1)).is_none());
    assert_eq!(row.get("deadline").cloned(), Some(DEFAULT_OSQUERY_DEADLINE_SECONDS.to_string()));
    assert_eq!(
        row.get("max_output").cloned(),
        Some(agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES.to_string())
    );
    let temp = fixture.state.join(TEMP_DIR_NAME);
    let temp_text = temp.display().to_string();
    assert!(row.get("environment").is_some_and(|text| text.contains("LC_ALL")
        && !text.contains("HOME")
        && text.contains(&format!("(\"TMPDIR\", \"{temp_text}\")"))
        && text.contains(&format!("(\"SQLITE_TMPDIR\", \"{temp_text}\")"))));
    assert_eq!(fs::metadata(&temp)?.permissions().mode() & MODE_BITS, OWNER_ONLY_DIR);
    assert_eq!(fs::metadata(&logger)?.permissions().mode() & MODE_BITS, OWNER_ONLY_DIR);
    assert!(row.values().any(|value| value == DISABLED_TABLES_FLAG));
    assert!(row.values().any(|value| value == "--disable_extensions"));
    let again = run_query(&env_of(&fixture, echo), &fixture.settings, query).await?;
    assert_eq!(again.rows.len(), 1);
    Ok(())
}


#[test]
fn the_spec_has_no_shell_and_the_query_last() -> TestResult {
    let fixture = fixture()?;
    let spec = query_spec(&fixture.settings, "/n", "/t", "/l", "SELECT 1");
    assert_eq!(spec.program, Path::new(NSENTER_PATH));
    assert_eq!(spec.arguments.last().and_then(|argument| argument.to_str()), Some("SELECT 1"));
    assert_eq!(spec.accepted_codes, vec![0]);
    Ok(())
}


#[tokio::test]
async fn more_rows_than_the_cap_are_refused_and_the_cap_itself_passes() -> TestResult {
    let fixture = fixture()?;
    let over = run_query(&env_of(&fixture, too_many_rows), &fixture.settings, "SELECT 1").await;
    assert_eq!(over, Err(OsqueryError::TooLarge));
    let at_cap = run_query(&env_of(&fixture, exactly_max_rows), &fixture.settings, "SELECT 1").await?;
    assert_eq!(at_cap.rows.len(), MAX_ROWS);
    Ok(())
}


#[test]
fn one_bad_row_is_refused_alone_and_counted() -> TestResult {
    let wide: serde_json::Map<String, Value> = (0..OVER_COLUMNS).map(|index| (format!("c{index}"), json!("v"))).collect();
    let at_columns: serde_json::Map<String, Value> = (0..MAX_COLUMNS).map(|index| (format!("c{index}"), json!("v"))).collect();
    let big_value = json!({"k": "a".repeat(MAX_VALUE_BYTES + 1)});
    let big_column = json!({"a".repeat(MAX_VALUE_BYTES + 1): "v"});
    let at_value = json!({"k": "a".repeat(MAX_VALUE_BYTES)});
    let escape = json!({"k": "\u{1b}[31mred"});
    let escape_column = json!({"\u{1b}k": "v"});
    let number = json!({"k": 1});
    let not_object = json!("text");
    let huge_row = json!({"k": "a".repeat(MAX_ROW_BYTES)});
    let rows = json!([
        {"name": "ok", "text": "line\nbreak\ttab\r"},
        wide,
        big_value,
        big_column,
        escape,
        escape_column,
        number,
        not_object,
        huge_row,
        at_columns,
        at_value,
        {"name": "last"}
    ]);
    let result = rows_from_output(&serde_json::to_vec(&rows)?)?;
    assert_eq!(result.refused_rows, REFUSED_ROWS);
    assert_eq!(result.rows.len(), KEPT_ROWS);
    assert_eq!(result.rows.first().and_then(|row| row.get("name")).map(String::as_str), Some("ok"));
    assert_eq!(result.rows.last().and_then(|row| row.get("name")).map(String::as_str), Some("last"));
    assert!(rows_from_output(b"[]")?.rows.is_empty());
    assert!(row_of("{}").is_some());
    assert!(has_control("\u{7f}"));
    assert!(!has_control("plain"));
    Ok(())
}


#[tokio::test]
async fn runner_failures_map_to_fixed_variants() -> TestResult {
    let fixture = fixture()?;
    let query = "SELECT 1";
    let run = |function: agent_linux::types::UpdateRunFn| {
        let env = env_of(&fixture, function);
        let settings = fixture.settings.clone();
        async move { run_query(&env, &settings, query).await }
    };
    assert_eq!(run(timeout).await, Err(OsqueryError::Deadline));
    assert_eq!(run(too_large).await, Err(OsqueryError::TooLarge));
    assert_eq!(run(exit_two).await, Err(OsqueryError::Exit(EXIT_CODE)));
    assert_eq!(run(killed).await, Err(OsqueryError::ResourceLimit));
    assert_eq!(run(no_start).await, Err(OsqueryError::Spawn(io::ErrorKind::NotFound)));
    let text = OsqueryError::ResourceLimit.to_string();
    assert!(["memory", "CPU time", "temp file size", "temp space"]
        .iter()
        .all(|limit| text.contains(limit)));
    let utf8 = std::str::from_utf8(&[INVALID_BYTE]).err().ok_or("valid")?;
    assert_eq!(osquery_error_of(SensorError::Utf8(utf8)), OsqueryError::NotJson { line: 0, column: 0 });
    assert_eq!(osquery_error_of(SensorError::Parse), OsqueryError::NotJson { line: 0, column: 0 });
    Ok(())
}


#[tokio::test]
async fn bad_json_gives_a_position_and_no_output_byte() -> TestResult {
    let fixture = fixture()?;
    let error = run_query(&env_of(&fixture, marked_garbage), &fixture.settings, "SELECT 1")
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, OsqueryError::NotJson { line, column } if line >= 1 && column >= 1));
    let mut texts = vec![error.to_string(), format!("{error:?}")];
    texts.extend(error.source().map(|cause| format!("{cause} {cause:?}")));
    assert!(error.source().is_none());
    assert!(texts.iter().all(|text| !text.contains(MARKER) && !text.contains('\u{1b}')));
    let not_array = rows_from_output(b"{\"a\":\"b\"}");
    assert!(matches!(not_array, Err(OsqueryError::NotJson { .. })));
    Ok(())
}


#[test]
fn queries_are_checked_before_any_run() -> TestResult {
    let long = "a".repeat(MAX_QUERY_BYTES + 1);
    let at_limit = "a".repeat(MAX_QUERY_BYTES);
    for (query, refused) in [
        ("", true),
        ("   \n", true),
        (long.as_str(), true),
        (at_limit.as_str(), false),
        ("SELECT\0 1", true),
        ("--extensions_socket=/tmp/x", true),
        (".shell id", true),
        (" -x", false),
        ("SELECT 1", false),
    ] {
        assert_eq!(check_query(query).is_err(), refused, "{query:.20}");
    }
    assert_eq!(query_fault("SELECT 1"), None);
    Ok(())
}


#[tokio::test]
async fn a_refused_query_never_starts_anything() -> TestResult {
    let fixture = fixture()?;
    let result = run_query(&env_of(&fixture, echo), &fixture.settings, "-x").await;
    assert!(matches!(result, Err(OsqueryError::BadQuery(_))));
    assert!(!fixture.state.join(LOGGER_DIR_NAME).exists());
    Ok(())
}


#[test]
fn the_program_is_judged_through_handles() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    let program = program_of(&fixture)?;
    assert_eq!(check_program(&program, uid), Ok(()));
    assert!(matches!(check_program(Path::new("/"), uid), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(check_program(Path::new("/tmp/.."), uid), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(
        check_program(Path::new("relative/osqueryi"), uid),
        Err(OsqueryError::Untrusted(_))
    ));
    let bin = program.parent().ok_or("no parent")?;
    assert_eq!(
        check_program(&bin.join("missing"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    assert_eq!(
        check_program(&bin.join("nodir").join("osqueryi"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    let link = bin.join("link");
    symlink(&program, &link)?;
    assert_eq!(check_program(&link, uid), Ok(()));
    let loop_a = bin.join("loop_a");
    symlink(&loop_a, &loop_a)?;
    assert!(matches!(check_program(&loop_a, uid), Err(OsqueryError::Spawn(_))));
    let sub = bin.join("sub");
    make_dir(&sub, PROGRAM_MODE)?;
    assert_eq!(check_program(&sub, uid), Err(OsqueryError::Untrusted("program is not a regular file")));
    let loose = bin.join("loose");
    fs::write(&loose, b"")?;
    fs::set_permissions(&loose, fs::Permissions::from_mode(GROUP_WRITABLE_PROGRAM))?;
    assert_eq!(
        check_program(&loose, uid),
        Err(OsqueryError::Untrusted("program is writable by group or others"))
    );
    assert!(matches!(check_program(&program, uid + 1), Err(OsqueryError::Untrusted(_))));
    let planted = fixture.state.join("planted");
    fs::write(&planted, b"")?;
    fs::set_permissions(&planted, fs::Permissions::from_mode(PROGRAM_MODE))?;
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(OPEN_DIR))?;
    let to_open_dir = bin.join("to_open_dir");
    symlink(&planted, &to_open_dir)?;
    assert!(matches!(check_program(&to_open_dir, uid), Err(OsqueryError::Untrusted(_))));
    fs::set_permissions(bin, fs::Permissions::from_mode(OPEN_DIR))?;
    assert!(matches!(check_program(&program, uid), Err(OsqueryError::Untrusted(_))));
    Ok(())
}


#[test]
fn the_fault_functions_name_each_case() -> TestResult {
    assert_eq!(program_fault(REGULAR_FILE_MODE, 0, 0), None);
    assert!(program_fault(DIRECTORY_MODE, 0, 0).is_some());
    assert!(program_fault(REGULAR_FILE_MODE, OTHER_USER, 0).is_some());
    assert!(program_fault(GROUP_WRITABLE_FILE_MODE, 0, 0).is_some());
    assert_eq!(logger_dir_fault(OWNER_ONLY_DIR, 0, 0), None);
    assert!(logger_dir_fault(OWNER_ONLY_DIR, OTHER_USER, 0).is_some());
    assert!(logger_dir_fault(OPEN_DIR, 0, 0).is_some());
    assert_eq!(errno_error(rustix::io::Errno::NOENT), OsqueryError::Spawn(io::ErrorKind::NotFound));
    Ok(())
}


#[test]
fn the_logger_directory_is_private_and_a_planted_one_is_refused() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    let made = prepare_logger_dir(&fixture.state, uid)?;
    assert_eq!(made, fixture.state.join(LOGGER_DIR_NAME));
    assert_eq!(prepare_logger_dir(&fixture.state, uid)?, made);
    fs::set_permissions(&made, fs::Permissions::from_mode(OPEN_DIR))?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Untrusted(_))));
    fs::remove_dir(&made)?;
    fs::write(&made, b"")?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Spawn(_))));
    fs::remove_file(&made)?;
    symlink(&fixture.state, &made)?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Spawn(_))));
    assert!(matches!(prepare_logger_dir(&fixture.state, uid + 1), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(prepare_logger_dir(Path::new("state"), uid), Err(OsqueryError::Untrusted(_))));
    assert_eq!(
        prepare_logger_dir(&fixture.state.join("missing"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    Ok(())
}


#[tokio::test]
async fn a_logger_path_that_is_not_utf8_is_refused() -> TestResult {
    let fixture = fixture()?;
    let odd = fixture.state.join(OsStr::from_bytes(&[b'd', INVALID_BYTE]));
    make_dir(&odd, OWNER_ONLY_DIR)?;
    let env = OsqueryEnv {
        state_dir: odd,
        trusted_uid: trusted_uid(),
        run: echo,
        release: release_ok,
        tools: fixture.tools.clone(),
    };
    let result = run_query(&env, &fixture.settings, "SELECT 1").await;
    assert_eq!(result, Err(OsqueryError::Untrusted("private directory is not UTF-8")));
    Ok(())
}


#[tokio::test]
async fn an_untrusted_tool_stops_the_run_before_any_directory_or_start() -> TestResult {
    let fixture = fixture()?;
    for index in 0..TOOL_COUNT {
        let mut tools = fixture.tools.clone();
        tools.splice(index..=index, [PathBuf::from("relative")]);
        let env = OsqueryEnv {
            tools,
            ..env_of(&fixture, recording)
        };
        let result = run_query(&env, &fixture.settings, "SELECT 1").await;
        assert!(matches!(result, Err(OsqueryError::Untrusted(_))), "tool {index}");
    }
    assert!(!fixture.state.join(LOGGER_DIR_NAME).exists());
    assert!(!fixture.state.join(TEMP_DIR_NAME).exists());
    Ok(())
}


#[test]
fn every_program_is_a_const_path() -> TestResult {
    let expected = [PRLIMIT_PATH, UNSHARE_PATH, NSENTER_PATH, MOUNT_PATH, UMOUNT_PATH, OSQUERYI_PATH].map(PathBuf::from);
    assert_eq!(tool_paths(), expected);
    assert!(tool_paths().iter().all(|path| path.is_absolute()));
    let fixture = fixture()?;
    let programs: Vec<PathBuf> = agent_linux::osquery::setup_steps(&fixture.settings, "/t", "/n")
        .into_iter()
        .map(|(_, spec)| spec.program)
        .chain([query_spec(&fixture.settings, "/n", "/t", "/l", "SELECT 1").program])
        .collect();
    assert_eq!(programs, [MOUNT_PATH, MOUNT_PATH, UNSHARE_PATH, NSENTER_PATH].map(PathBuf::from));
    Ok(())
}


pub fn counting_builder(raw: &str, calls: &mut usize) -> Option<std::collections::BTreeMap<String, String>> {
    *calls += 1;
    row_of(raw)
}


const TWO_ROWS: &[u8] = b"[{\"a\":\"b\"},{\"c\":\"d\"}]";


const TWO_ROWS_COUNT: usize = 2;


#[test]
fn the_row_count_bound_is_applied_before_any_row_is_built() -> TestResult {
    let over: Vec<Value> = (0..=MAX_ROWS).map(|index| json!({"k": index.to_string()})).collect();
    let mut calls = 0;
    let refused = rows_with_builder(&serde_json::to_vec(&over)?, counting_builder, &mut calls);
    assert_eq!(refused, Err(OsqueryError::TooLarge));
    assert_eq!(calls, 0);
    let two = rows_with_builder(TWO_ROWS, counting_builder, &mut calls)?;
    assert_eq!(two.rows.len(), TWO_ROWS_COUNT);
    assert_eq!(calls, TWO_ROWS_COUNT);
    Ok(())
}


const DISABLED_TABLES_FLAG: &str = "--disable_tables=curl,curl_certificate,carves,ec2_instance_metadata,ec2_instance_tags,azure_instance_metadata,azure_instance_tags,ycloud_instance_metadata";


const WRAPPER_ARGUMENTS: usize = 10;


fn read_calls(fixture: &Fixture) -> io::Result<Vec<String>> {
    let log = fixture.state.join(TEMP_DIR_NAME).join(CALL_LOG);
    Ok(fs::read_to_string(log)?.lines().map(str::to_owned).collect())
}


fn call_names(calls: &[String]) -> Vec<&str> {
    calls.iter().filter_map(|call| call.split(' ').next()).collect()
}


#[tokio::test]
async fn the_namespace_is_prepared_in_order_and_dropped_after_the_run() -> TestResult {
    let fixture = fixture()?;
    let result = run_query(&env_of(&fixture, recording), &fixture.settings, "SELECT 1").await?;
    assert_eq!(result.rows.len(), 0);
    let calls = read_calls(&fixture)?;
    assert_eq!(
        call_names(&calls),
        ["umount", "umount", "mount", "mount", "unshare", "nsenter", "umount", "umount"]
    );
    let ns_file = fixture.state.join(TEMP_DIR_NAME).join(NAMESPACE_FILE_NAME);
    let temp_dir = fixture.state.join(TEMP_DIR_NAME);
    assert_eq!(calls.first().cloned(), Some(format!("umount {}", ns_file.display())));
    assert_eq!(calls.get(1).cloned(), Some(format!("umount {}", temp_dir.display())));
    assert_eq!(
        calls.get(SELF_BIND_CALL).cloned(),
        Some(format!("mount --bind {0} {0}", temp_dir.display()))
    );
    assert_eq!(
        calls.get(MAKE_PRIVATE_CALL).cloned(),
        Some(format!("mount --make-private {}", temp_dir.display()))
    );
    let size = format!("size={DEFAULT_OSQUERY_TEMP_TOTAL_BYTES},mode=1777,nosuid,nodev");
    let create = calls.get(CREATE_CALL).ok_or("no create")?;
    assert!(create.contains("--mount=") && create.contains("--propagation=private -- ") && create.contains(&size));
    assert!(create.ends_with(&format!("tmpfs {}", temp_dir.display())));
    let shared_temp_paths = ["/tmp", "/var/tmp", "/usr/tmp"];
    assert!(calls.iter().all(|call| call.split(' ').all(|word| !shared_temp_paths.contains(&word))));
    assert_eq!(fs::metadata(&ns_file)?.permissions().mode() & MODE_BITS, OWNER_ONLY_FILE);
    Ok(())
}


#[tokio::test]
async fn a_failed_step_names_itself_keeps_its_cause_and_the_guard_drops_the_namespace() -> TestResult {
    let fixture = fixture()?;
    let failed = run_query(&env_of(&fixture, unshare_fails), &fixture.settings, "SELECT 1").await;
    assert_eq!(
        failed,
        Err(OsqueryError::Sandbox {
            step: "namespace",
            source: Box::new(OsqueryError::Exit(1)),
        })
    );
    let error = failed.err().ok_or("accepted")?;
    assert!(error.source().is_some_and(|cause| cause.to_string().contains("status 1")));
    assert_eq!(
        call_names(&read_calls(&fixture)?),
        ["umount", "umount", "mount", "mount", "unshare", "umount", "umount"]
    );
    Ok(())
}


#[test]
fn the_guard_runs_the_release_step_on_drop_and_a_failure_is_counted() -> TestResult {
    let fixture = fixture()?;
    let temp = agent_linux::osquery::prepare_temp_dir(&fixture.state, trusted_uid())?;
    let targets = vec![temp.join(NAMESPACE_FILE_NAME), temp.clone()];
    drop(NamespaceGuard {
        release: release_ok,
        targets: targets.clone(),
    });
    assert_eq!(call_names(&read_calls(&fixture)?), ["umount", "umount"]);
    drop(NamespaceGuard {
        release: release_fails,
        targets: targets.clone(),
    });
    assert_eq!(call_names(&read_calls(&fixture)?).len(), RELEASE_CALLS_AFTER_TWO_DROPS);
    assert_eq!(release_mounts(&targets, release_fails), TARGET_COUNT);
    assert_eq!(release_mounts(&targets, release_ok), 0);
    assert!(umount_path(&fixture.state.join("not-a-mount")).is_err());
    Ok(())
}


#[tokio::test]
async fn a_failed_release_is_logged_not_fatal_and_a_full_tmpfs_is_a_resource_limit() -> TestResult {
    let fixture = fixture()?;
    let env = OsqueryEnv {
        release: release_fails,
        ..env_of(&fixture, recording)
    };
    let passed = run_query(&env, &fixture.settings, "SELECT 1").await?;
    assert!(passed.rows.is_empty());
    let full = run_query(&env_of(&fixture, sqlite_full), &fixture.settings, "SELECT 1").await;
    assert_eq!(full, Err(OsqueryError::ResourceLimit));
    assert_eq!(osquery_error_of(SensorError::Exit(Some(EXIT_CODE))), OsqueryError::Exit(EXIT_CODE));
    Ok(())
}


#[test]
fn the_setup_chain_mounts_only_the_private_directory_with_the_exact_size() -> TestResult {
    let fixture = fixture()?;
    let steps = agent_linux::osquery::setup_steps(&fixture.settings, "/dir", "/ns");
    assert_eq!(
        steps.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["self-bind", "make-private", "namespace"]
    );
    let (_, create) = steps.get(CREATE_STEP).ok_or("no step")?;
    assert_eq!(create.program, Path::new(UNSHARE_PATH));
    let words: Vec<String> = create.arguments.iter().map(|argument| argument.to_string_lossy().into_owned()).collect();
    let head = ["--mount=/ns", "--propagation=private", "--"].map(str::to_owned);
    assert_eq!(words.get(..HEAD_WORDS), Some(&head[..]));
    assert_eq!(words.get(HEAD_WORDS).map(String::as_str), Some(MOUNT_PATH));
    let tail = [
        "-t".to_owned(),
        "tmpfs".to_owned(),
        "-o".to_owned(),
        format!("size={DEFAULT_OSQUERY_TEMP_TOTAL_BYTES},mode=1777,nosuid,nodev"),
        "tmpfs".to_owned(),
        "/dir".to_owned(),
    ];
    assert_eq!(words.get(HEAD_WORDS + 1..), Some(&tail[..]));
    assert!(steps
        .iter()
        .all(|(_, spec)| spec.accepted_codes == vec![0] && spec.max_output < agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES));
    Ok(())
}


#[test]
fn the_namespace_file_is_made_once_and_never_through_a_symlink() -> TestResult {
    let fixture = fixture()?;
    let temp = agent_linux::osquery::prepare_temp_dir(&fixture.state, trusted_uid())?;
    let made = agent_linux::osquery::prepare_namespace_file(&temp)?;
    assert_eq!(agent_linux::osquery::prepare_namespace_file(&temp)?, made);
    fs::remove_file(&made)?;
    symlink(&fixture.state, &made)?;
    assert!(matches!(
        agent_linux::osquery::prepare_namespace_file(&temp),
        Err(OsqueryError::Untrusted(_))
    ));
    assert!(matches!(
        agent_linux::osquery::prepare_namespace_file(&fixture.state.join("missing")),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    ));
    Ok(())
}


#[test]
fn the_lock_file_is_judged_through_its_handle() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    let regular = rustix::fs::FileType::RegularFile.as_raw_mode();
    assert_eq!(agent_linux::osquery::lock_fault(regular | OWNER_ONLY_FILE, uid, uid), None);
    assert!(agent_linux::osquery::lock_fault(OWNER_ONLY_FILE, uid, uid).is_some_and(|reason| reason.contains("regular")));
    assert!(agent_linux::osquery::lock_fault(regular | OWNER_ONLY_FILE, uid + 1, uid).is_some_and(|reason| reason.contains("owned")));
    assert!(agent_linux::osquery::lock_fault(regular | OPEN_DIR, uid, uid).is_some_and(|reason| reason.contains("open")));
    let lock = fixture.state.join(agent_linux::osquery::LOCK_FILE_NAME);
    agent_linux::osquery::open_lock_file(&fixture.state, uid)?;
    assert_eq!(fs::metadata(&lock)?.permissions().mode() & MODE_BITS, OWNER_ONLY_FILE);
    fs::set_permissions(&lock, fs::Permissions::from_mode(OPEN_DIR))?;
    assert!(matches!(
        agent_linux::osquery::open_lock_file(&fixture.state, uid),
        Err(OsqueryError::Untrusted(_))
    ));
    fs::remove_file(&lock)?;
    symlink(&fixture.state, &lock)?;
    assert!(matches!(
        agent_linux::osquery::open_lock_file(&fixture.state, uid),
        Err(OsqueryError::Untrusted(_))
    ));
    assert!(matches!(
        agent_linux::osquery::open_lock_file(&fixture.state.join("missing"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    ));
    Ok(())
}


#[tokio::test]
async fn a_second_query_fails_busy_past_its_deadline_and_mounts_nothing() -> TestResult {
    let fixture = fixture()?;
    let held = agent_linux::osquery::lock_state(&fixture.state, trusted_uid(), 1).await?;
    let settings = OsquerySettings {
        deadline_seconds: 1,
        ..fixture.settings.clone()
    };
    let refused = run_query(&env_of(&fixture, recording), &settings, "SELECT 1").await;
    assert_eq!(refused, Err(OsqueryError::Busy));
    assert!(refused.err().ok_or("accepted")?.to_string().contains("did not finish"));
    assert!(!fixture.state.join(TEMP_DIR_NAME).exists());
    drop(held);
    Ok(())
}


#[tokio::test]
async fn a_second_query_runs_once_the_first_releases_the_lock() -> TestResult {
    let fixture = fixture()?;
    let held = agent_linux::osquery::lock_state(&fixture.state, trusted_uid(), 1).await?;
    let env = env_of(&fixture, recording);
    let (waiting, ()) = tokio::join!(run_query(&env, &fixture.settings, "SELECT 1"), async { drop(held) });
    assert!(waiting?.rows.is_empty());
    assert_eq!(call_names(&read_calls(&fixture)?).len(), RUN_CALLS);
    Ok(())
}


#[tokio::test]
async fn a_lock_that_cannot_be_taken_for_another_reason_is_a_spawn_error() -> TestResult {
    let handle = rustix::fs::open("/", rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty())?;
    assert!(matches!(
        agent_linux::osquery::lock_exclusive(&handle, 0).await,
        Err(OsqueryError::Spawn(_))
    ));
    Ok(())
}


const GATE_FILE: &str = "gate";


const MAX_SPINS: usize = 1_000_000;


const IDLE_SPINS: usize = 200;


const FIRST_RUN_CALLS_BEFORE_QUERY: usize = 6;


const BOTH_RUNS_CALLS: usize = 16;


const PROBES_PER_RUN: usize = 4;


const RUNS: usize = 2;


const TWO_POLLS: u64 = 2;


const MANY_POLLS: u64 = 100_000;


fn temp_dir_in(spec: &agent_linux::model::CommandSpec) -> Option<PathBuf> {
    spec.arguments
        .iter()
        .filter_map(|argument| argument.to_str())
        .map(|argument| argument.trim_start_matches("--mount="))
        .find_map(|argument| argument.find(TEMP_DIR_NAME).and_then(|at| argument.get(..at + TEMP_DIR_NAME.len())))
        .map(PathBuf::from)
}


async fn wait_for_file(path: Option<PathBuf>) {
    let mut spins = 0;
    while path.as_ref().is_some_and(|file| !file.exists()) && spins < MAX_SPINS {
        tokio::task::yield_now().await;
        spins += 1;
    }
}


fn gated(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let gate = temp_dir_in(&spec).and_then(|directory| directory.parent().map(|parent| parent.join(GATE_FILE)));
    let holds = program_name(&spec) == "nsenter";
    let logged = recording(spec, deadline);
    if holds {
        Box::pin(async move {
            let body = logged.await?;
            wait_for_file(gate).await;
            Ok(body)
        })
    } else {
        logged
    }
}


fn release_probing_the_lock(path: &Path) -> io::Result<()> {
    log_release(path)?;
    let directory = path.ancestors().find(|ancestor| ancestor.ends_with(TEMP_DIR_NAME));
    directory.map_or(Ok(()), |found| {
        let lock = found.parent().map(|parent| parent.join(agent_linux::osquery::LOCK_FILE_NAME));
        let probe = fs::File::open(lock.ok_or_else(|| io::Error::other("no parent"))?)?;
        let verdict = match rustix::fs::flock(&probe, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => "probe free\n",
            Err(_) => "probe held\n",
        };
        fs::OpenOptions::new()
            .append(true)
            .open(found.join(CALL_LOG))?
            .write_all(verdict.as_bytes())
    })
}


fn real_calls(log: &Path) -> io::Result<Vec<String>> {
    match fs::read_to_string(log) {
        Ok(text) => Ok(text.lines().filter(|line| !line.starts_with("probe")).map(str::to_owned).collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}


async fn observe_first_run(state: &Path) -> io::Result<Vec<String>> {
    let log = state.join(TEMP_DIR_NAME).join(CALL_LOG);
    let mut spins = 0;
    while real_calls(&log)?.len() < FIRST_RUN_CALLS_BEFORE_QUERY && spins < MAX_SPINS {
        tokio::task::yield_now().await;
        spins += 1;
    }
    for _ in 0..IDLE_SPINS {
        tokio::task::yield_now().await;
    }
    let snapshot = real_calls(&log)?;
    fs::write(state.join(GATE_FILE), b"")?;
    Ok(snapshot)
}


#[tokio::test]
async fn a_second_query_sets_up_nothing_until_the_first_has_released_its_mounts() -> TestResult {
    let fixture = fixture()?;
    let env = OsqueryEnv {
        release: release_probing_the_lock,
        ..env_of(&fixture, gated)
    };
    let (first, second, snapshot) = tokio::join!(
        run_query(&env, &fixture.settings, "SELECT 1"),
        run_query(&env, &fixture.settings, "SELECT 2"),
        observe_first_run(&fixture.state)
    );
    assert!(first?.rows.is_empty());
    assert!(second?.rows.is_empty());
    let during = snapshot?;
    assert_eq!(call_names(&during), ["umount", "umount", "mount", "mount", "unshare", "nsenter"]);
    let log = fixture.state.join(TEMP_DIR_NAME).join(CALL_LOG);
    let all = real_calls(&log)?;
    assert_eq!(all.len(), BOTH_RUNS_CALLS);
    assert_eq!(all.get(..FIRST_RUN_CALLS_BEFORE_QUERY), Some(&during[..]));
    let text = fs::read_to_string(&log)?;
    assert_eq!(text.matches("probe held").count(), RUNS * PROBES_PER_RUN);
    assert_eq!(text.matches("probe free").count(), 0);
    Ok(())
}


#[tokio::test]
async fn a_fifo_or_socket_at_the_lock_or_namespace_path_is_refused_at_once() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    let lock = fixture.state.join(agent_linux::osquery::LOCK_FILE_NAME);
    let owner = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
    rustix::fs::mknodat(rustix::fs::CWD, &lock, rustix::fs::FileType::Fifo, owner, 0)?;
    assert!(matches!(
        agent_linux::osquery::open_lock_file(&fixture.state, uid),
        Err(OsqueryError::Untrusted(reason)) if reason.contains("regular")
    ));
    assert!(matches!(
        run_query(&env_of(&fixture, recording), &fixture.settings, "SELECT 1").await,
        Err(OsqueryError::Untrusted(_))
    ));
    assert!(!fixture.state.join(TEMP_DIR_NAME).exists());
    fs::remove_file(&lock)?;
    let temp = agent_linux::osquery::prepare_temp_dir(&fixture.state, uid)?;
    rustix::fs::mknodat(rustix::fs::CWD, temp.join(NAMESPACE_FILE_NAME), rustix::fs::FileType::Fifo, owner, 0)?;
    assert!(matches!(
        agent_linux::osquery::prepare_namespace_file(&temp),
        Err(OsqueryError::Untrusted(reason)) if reason.contains("regular")
    ));
    let directory = fs::File::open(&fixture.state)?;
    let short = format!(
        "/proc/self/fd/{}/{}",
        std::os::fd::AsRawFd::as_raw_fd(&directory),
        agent_linux::osquery::LOCK_FILE_NAME
    );
    let bound = std::os::unix::net::UnixListener::bind(short)?;
    assert!(matches!(
        agent_linux::osquery::open_lock_file(&fixture.state, uid),
        Err(OsqueryError::Untrusted(reason)) if reason.contains("regular")
    ));
    drop(bound);
    Ok(())
}


#[test]
fn a_name_the_kernel_refuses_is_a_spawn_error_and_a_free_name_is_created_private() -> TestResult {
    let fixture = fixture()?;
    let directory = rustix::fs::open(
        &fixture.state,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    let too_long = "x".repeat(LONG_NAME_BYTES);
    assert!(matches!(
        agent_linux::osquery::open_regular(&directory, &too_long, "not regular"),
        Err(OsqueryError::Spawn(_))
    ));
    agent_linux::osquery::open_regular(&directory, "fresh", "not regular")?;
    assert_eq!(
        fs::metadata(fixture.state.join("fresh"))?.permissions().mode() & MODE_BITS,
        OWNER_ONLY_FILE
    );
    Ok(())
}


const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);


fn kill_nothing(_child: &mut std::process::Child) -> io::Result<()> {
    Ok(())
}


fn kill_fails(_child: &mut std::process::Child) -> io::Result<()> {
    Err(io::Error::other("kill refused"))
}


#[test]
fn a_failed_kill_still_waits_for_the_child() -> TestResult {
    let mut child = std::process::Command::new("/usr/bin/true").spawn()?;
    let proc_entry = PathBuf::from(format!("/proc/{}", child.id()));
    let failure = agent_linux::osquery::reap_killed(&mut child, kill_fails, MANY_POLLS, REAP_INTERVAL);
    assert!(failure.is_err_and(|error| error.to_string().contains("kill refused")));
    assert!(!proc_entry.exists());
    let mut sleeper = std::process::Command::new("/usr/bin/sleep").arg("600").spawn()?;
    agent_linux::osquery::reap_killed(&mut sleeper, std::process::Child::kill, MANY_POLLS, REAP_INTERVAL)?;
    let mut stuck = std::process::Command::new("/usr/bin/sleep").arg("600").spawn()?;
    let unreaped = agent_linux::osquery::reap_killed(&mut stuck, kill_nothing, TWO_POLLS, REAP_INTERVAL);
    assert!(unreaped.is_err_and(|error| error.to_string().contains("not reaped")));
    stuck.kill()?;
    stuck.wait()?;
    Ok(())
}


fn release_waits_for_marker(path: &Path) -> io::Result<()> {
    (0..MARKER_POLLS)
        .find_map(|_| {
            path.exists().then_some(Ok(())).or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(MARKER_POLL_MILLISECONDS));
                None
            })
        })
        .unwrap_or_else(|| Err(io::Error::other("marker never appeared")))
}


fn release_panics(_path: &Path) -> io::Result<()> {
    let removed = Vec::<u8>::new().remove(0);
    Err(io::Error::other(removed.to_string()))
}


fn lock_handle(fixture: &Fixture) -> Result<std::sync::Arc<std::os::fd::OwnedFd>, Box<dyn Error>> {
    Ok(std::sync::Arc::new(agent_linux::osquery::open_lock_file(&fixture.state, trusted_uid())?))
}


const DEVICE: u64 = 1;


const INODE: u64 = 2;


const OTHER_INODE: u64 = 3;


const OTHER_DEVICE: u64 = 4;


#[test]
fn a_reopened_handle_must_be_the_anchored_file() -> TestResult {
    assert!(agent_linux::osquery::same_identity((DEVICE, INODE), (DEVICE, INODE), "x").is_ok());
    assert!(matches!(
        agent_linux::osquery::same_identity((DEVICE, INODE), (DEVICE, OTHER_INODE), "x"),
        Err(OsqueryError::Untrusted("x"))
    ));
    assert!(matches!(
        agent_linux::osquery::same_identity((DEVICE, INODE), (OTHER_DEVICE, INODE), "x"),
        Err(OsqueryError::Untrusted("x"))
    ));
    Ok(())
}


const RELEASES_BEFORE_CANCEL: usize = 3;


const MOUNTS_OF_ONE_RUN: usize = 2;


const HOLD_FILE: &str = "hold";


const GO_FILE: &str = "go";


fn holding(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let hold = temp_dir_in(&spec).and_then(|directory| directory.parent().map(|parent| parent.join(HOLD_FILE)));
    let written = hold.map_or(Ok(()), |path| fs::write(path, b"")).map_err(SensorError::Io);
    let logged = recording(spec, deadline);
    Box::pin(async move {
        written?;
        logged.await
    })
}


fn release_held_until_go(path: &Path) -> io::Result<()> {
    log_release(path)?;
    let state = path.ancestors().find(|ancestor| ancestor.ends_with(TEMP_DIR_NAME)).and_then(Path::parent);
    state.map_or(Ok(()), |found| {
        (0..MARKER_POLLS)
            .find_map(|_| {
                (!found.join(HOLD_FILE).exists() || found.join(GO_FILE).exists())
                    .then_some(())
                    .or_else(|| {
                        std::thread::sleep(std::time::Duration::from_millis(MARKER_POLL_MILLISECONDS));
                        None
                    })
            })
            .ok_or_else(|| io::Error::other("go never appeared"))
    })
}


async fn wait_for_calls(log: &Path, prefix: &str, count: usize) -> io::Result<()> {
    let mut polls = 0;
    while real_calls(log)?.iter().filter(|line| line.starts_with(prefix)).count() < count && polls < MARKER_POLLS {
        tokio::time::sleep(std::time::Duration::from_millis(MARKER_POLL_MILLISECONDS)).await;
        polls += 1;
    }
    Ok(())
}


#[tokio::test]
async fn a_cancelled_query_keeps_the_lock_until_its_release_has_finished() -> TestResult {
    let fixture = fixture()?;
    let env = OsqueryEnv {
        release: release_held_until_go,
        ..env_of(&fixture, holding)
    };
    let log = fixture.state.join(TEMP_DIR_NAME).join(CALL_LOG);
    let mut first = Box::pin(run_query(&env, &fixture.settings, "SELECT 1"));
    let first_ended = tokio::select! {
        outcome = &mut first => Some(outcome.is_ok()),
        reached = wait_for_calls(&log, "umount", RELEASES_BEFORE_CANCEL) => reached.map(|()| None)?,
    };
    assert_eq!(first_ended, None);
    drop(first);
    let probe = agent_linux::osquery::open_lock_file(&fixture.state, trusted_uid())?;
    assert!(matches!(agent_linux::osquery::lock_exclusive(&probe, 0).await, Err(OsqueryError::Busy)));
    let during = real_calls(&log)?;
    assert_eq!(during.iter().filter(|line| line.starts_with("umount")).count(), RELEASES_BEFORE_CANCEL);
    assert_eq!(during.iter().filter(|line| line.starts_with("mount")).count(), MOUNTS_OF_ONE_RUN);
    fs::write(fixture.state.join(GO_FILE), b"")?;
    agent_linux::osquery::lock_exclusive(&probe, MARKER_POLLS).await?;
    drop(probe);
    assert!(run_query(&env, &fixture.settings, "SELECT 2").await?.rows.is_empty());
    Ok(())
}


const SWAP_COUNT: usize = 3;


const LAST_SWAP: usize = 2;


fn swap_for_fifo(directory: &std::os::fd::OwnedFd, name: &str) {
    let removed = rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty());
    let made = rustix::fs::mknodat(directory, name, rustix::fs::FileType::Fifo, rustix::fs::Mode::RUSR, 0);
    tracing::debug!(?removed, ?made, "swapped for a fifo");
}


fn swap_for_symlink(directory: &std::os::fd::OwnedFd, name: &str) {
    let removed = rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty());
    let made = rustix::fs::symlinkat("/dev/null", directory, name);
    tracing::debug!(?removed, ?made, "swapped for a symlink");
}


fn swap_for_other_file(directory: &std::os::fd::OwnedFd, name: &str) {
    let removed = rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty());
    let made = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL | rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::RUSR,
    );
    tracing::debug!(?removed, made = made.is_ok(), "swapped for another file");
}


#[test]
fn a_name_swapped_between_the_anchor_and_the_reopen_is_refused() -> TestResult {
    let fixture = fixture()?;
    let directory = rustix::fs::open(
        &fixture.state,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?;
    let swaps: [agent_linux::types::NameSwapFn; SWAP_COUNT] = [swap_for_fifo, swap_for_symlink, swap_for_other_file];
    let outcomes = swaps
        .iter()
        .enumerate()
        .map(|(index, swap)| {
            let name = format!("swapped-{index}");
            fs::write(fixture.state.join(&name), b"")?;
            Ok(agent_linux::osquery::open_regular_between(&directory, &name, "not regular", *swap).map(|_file| ()))
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    assert!(matches!(outcomes.first(), Some(Err(OsqueryError::Untrusted("not regular")))));
    assert!(matches!(outcomes.get(1), Some(Err(OsqueryError::Spawn(_)))));
    assert!(matches!(outcomes.get(LAST_SWAP), Some(Err(OsqueryError::Untrusted("not regular")))));
    Ok(())
}


#[tokio::test(flavor = "current_thread")]
async fn the_release_runs_off_the_async_worker() -> TestResult {
    let fixture = fixture()?;
    let marker = fixture.state.join("marker");
    let writer = async {
        tokio::time::sleep(std::time::Duration::from_millis(MARKER_POLL_MILLISECONDS)).await;
        fs::write(&marker, b"x")
    };
    let (failed, written) = tokio::join!(
        agent_linux::osquery::release_off_runtime(release_waits_for_marker, vec![marker.clone()], lock_handle(&fixture)?),
        writer
    );
    written?;
    assert_eq!(failed, 0);
    let targets = vec![fixture.state.clone(), fixture.state.join("other")];
    assert_eq!(
        agent_linux::osquery::release_off_runtime(release_fails, targets.clone(), lock_handle(&fixture)?).await,
        TARGET_COUNT
    );
    assert_eq!(
        agent_linux::osquery::release_off_runtime(release_panics, targets, lock_handle(&fixture)?).await,
        TARGET_COUNT
    );
    Ok(())
}


const LONG_NAME_BYTES: usize = 300;


const MARKER_POLLS: u64 = 500;


const MARKER_POLL_MILLISECONDS: u64 = 10;


#[test]
fn the_release_step_has_the_cleared_environment_and_a_deadline() -> TestResult {
    let interval = std::time::Duration::from_millis(1);
    let printenv = Path::new("/usr/bin/printenv");
    agent_linux::osquery::bounded_status(printenv, Path::new("PATH"), MANY_POLLS, interval)?;
    assert!(agent_linux::osquery::bounded_status(printenv, Path::new("CARGO_MANIFEST_DIR"), MANY_POLLS, interval).is_err());
    let slow = agent_linux::osquery::bounded_status(Path::new("/usr/bin/sleep"), Path::new("600"), TWO_POLLS, interval);
    assert!(slow.is_err_and(|error| error.to_string().contains("timed out")));
    assert!(agent_linux::osquery::bounded_status(Path::new("/nonexistent/umount"), Path::new("/"), MANY_POLLS, interval).is_err());
    Ok(())
}
