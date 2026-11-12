mod support;


use clap::Parser;
use serde_json::Value;
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use support::{
    broken_input, invoke, live_args, mode_of, offline_args, session_file, set_mode, start_live, words, BrokenOutput, Live, TestError, TestResult,
    OWNER_ONLY, PASSWORD, USER,
};
use tempfile::tempdir;
use xdrctl::alerts::{list_path, map_status, valid_cursor, valid_id};
use xdrctl::cli::{execute, render, render_error, run_reporting};
use xdrctl::commands::{is_yaml, server_address, yaml_files};
use xdrctl::error::{CliError, ClientError};
use xdrctl::http::{build_agent, send_request};
use xdrctl::model::{Cli, Context, HttpMethod, HttpReply, HttpRequest, OutputFormat, Report, Session};
use xdrctl::session::{load_session, remove_session, save_session, session_path};
use xdrctl::types::SendFn;


const SUCCESS: &str = "ExitCode(unix_exit_status(0))";


const FAILURE: &str = "ExitCode(unix_exit_status(1))";


const USAGE_FAILURE: &str = "ExitCode(unix_exit_status(2))";


const CHANGES: usize = 3;


const RECORDS: u64 = 3;


const STATUS_OK: u16 = 200;


const STATUS_ERROR: u16 = 500;


const MODULE_OK: &str = include_str!("../../core-config/tests/fixtures/module_ok.yaml");


const PLATFORM_OK: &str = include_str!("../../core-config/tests/fixtures/platform_ok.yaml");


const MODULE_BAD: &str = include_str!("../../core-config/tests/fixtures/module_unknown_field.yaml");


const WORLD_READABLE: u32 = 0o644;


#[cfg(unix)]
const READ_ONLY: u32 = 0o500;


#[cfg(unix)]
const FULL_OWNER: u32 = 0o700;


const FAKE_SERVER: &str = "https://example.test";


fn fixed(status: u16, body: &'static str) -> impl Fn(Option<&Path>, &HttpRequest) -> Result<HttpReply, ClientError> {
    move |_, _| {
        Ok(HttpReply {
            status,
            body: body.to_owned(),
        })
    }
}


fn store_session(dir: &Path) -> TestResult {
    save_session(
        &session_path(dir),
        &Session {
            server: FAKE_SERVER.to_owned(),
            token: "stored-token".to_owned(),
        },
    )?;
    Ok(())
}


fn login_live(live: &Live) -> Result<String, TestError> {
    let outcome = invoke(&live_args(live, &["login", "--username", USER]), &format!("{PASSWORD}\n"), &send_request)?;
    assert_eq!(outcome.code, SUCCESS, "{}", outcome.err);
    Ok(fs::read_to_string(session_file(live))?)
}


#[test]
fn full_session_against_the_live_api() -> TestResult {
    let live = start_live()?;
    let stored = login_live(&live)?;
    let session: Value = serde_json::from_str(&stored)?;
    let token = session.get("token").and_then(Value::as_str).ok_or("no token stored")?.to_owned();
    assert_eq!(mode_of(&session_file(&live))?, OWNER_ONLY);

    let who = invoke(&live_args(&live, &["whoami"]), "", &send_request)?;
    assert_eq!(who.code, SUCCESS);
    assert_eq!(who.out, "reader roles=reader mfa=false\n");

    let json = invoke(&live_args(&live, &["--output", "json", "whoami"]), "", &send_request)?;
    let parsed: Value = serde_json::from_str(&json.out)?;
    assert_eq!(parsed.get("username").and_then(Value::as_str), Some(USER));

    let desired = live.dir.path().join("desired");
    let state = live.dir.path().join("state");
    let audit = live.dir.path().join("client-audit.log");
    fs::create_dir_all(&desired)?;
    fs::create_dir_all(&state)?;
    fs::write(desired.join("a.yaml"), "one\n")?;
    fs::write(desired.join("b.yaml"), "two\n")?;
    fs::write(state.join("b.yaml"), "old\n")?;
    fs::write(state.join("stray.yaml"), "stray\n")?;
    let desired_text = desired.display().to_string();
    let state_text = state.display().to_string();
    let audit_text = audit.display().to_string();

    let planned = invoke(&live_args(&live, &["plan", &desired_text, "--state", &state_text]), "", &send_request)?;
    assert_eq!(planned.code, SUCCESS);
    assert!(planned.out.contains("Create a.yaml"));
    assert!(planned.out.contains("Update b.yaml"));
    assert!(planned.out.contains("Delete stray.yaml"));

    let planned_json = invoke(
        &live_args(&live, &["--output", "json", "plan", &desired_text, "--state", &state_text]),
        "",
        &send_request,
    )?;
    let actions: Value = serde_json::from_str(&planned_json.out)?;
    assert_eq!(actions.as_array().map(Vec::len), Some(CHANGES));
    assert_eq!(
        actions.get(0).and_then(|first| first.get("action")).and_then(Value::as_str),
        Some("config.create")
    );

    let apply_args = [
        "apply",
        &desired_text,
        "--state",
        &state_text,
        "--audit-file",
        &audit_text,
        "--justification",
        "ticket 1",
    ];
    let declined = invoke(&live_args(&live, &apply_args), "n\n", &send_request)?;
    assert_eq!(declined.code, FAILURE);
    assert!(declined.err.contains("apply cancelled"));
    assert!(declined.err.contains(&format!("Apply {CHANGES} change(s)? [y/N]")));
    assert!(!state.join("a.yaml").exists());

    let confirmed = invoke(&live_args(&live, &apply_args), "YES\n", &send_request)?;
    assert_eq!(confirmed.code, SUCCESS, "{}", confirmed.err);
    assert_eq!(confirmed.out, "applied 3\n");
    assert_eq!(fs::read_to_string(state.join("a.yaml"))?, "one\n");
    assert!(!state.join("stray.yaml").exists());

    let audited = fs::read_to_string(&audit)?;
    assert!(audited.contains("\"actor_id\":\"reader\""));
    assert!(audited.contains("ticket 1"));

    let verified = invoke(&live_args(&live, &["audit", "verify", &audit_text]), "", &send_request)?;
    assert_eq!(verified.code, SUCCESS);
    assert!(verified.out.starts_with("ok 3 records head "));
    let verified_json = invoke(
        &live_args(&live, &["--output", "json", "audit", "verify", &audit_text]),
        "",
        &send_request,
    )?;
    let report: Value = serde_json::from_str(&verified_json.out)?;
    assert_eq!(report.get("records").and_then(Value::as_u64), Some(RECORDS));

    fs::write(&audit, audited.replacen("ticket 1", "ticket 2", 1))?;
    let tampered = invoke(&live_args(&live, &["audit", "verify", &audit_text]), "", &send_request)?;
    assert_eq!(tampered.code, FAILURE);

    let skipped = invoke(
        &live_args(
            &live,
            &[
                "apply",
                &desired_text,
                "--state",
                &state_text,
                "--audit-file",
                &audit_text,
                "--justification",
                "j",
                "--yes",
            ],
        ),
        "",
        &send_request,
    )?;
    assert_eq!(skipped.code, FAILURE);

    let out = invoke(&live_args(&live, &["logout"]), "", &send_request)?;
    assert_eq!(out.code, SUCCESS);
    assert_eq!(out.out, "logged out\n");
    assert!(!session_file(&live).exists());
    let after = invoke(&live_args(&live, &["whoami"]), "", &send_request)?;
    assert_eq!(after.code, FAILURE);
    assert!(after.err.contains("not logged in"));

    let everything = [
        who.out,
        json.out,
        planned.out,
        planned_json.out,
        declined.err,
        confirmed.out,
        verified.out,
        out.out,
        after.err,
    ]
    .join("");
    assert!(!everything.contains(&token));
    Ok(())
}


#[test]
fn login_failures_and_json_output() -> TestResult {
    let live = start_live()?;
    let wrong = invoke(&live_args(&live, &["login", "--username", USER]), "wrong password\n", &send_request)?;
    assert_eq!(wrong.code, FAILURE);
    assert!(wrong.err.contains("invalid_credentials"));
    assert!(!session_file(&live).exists());

    let json_wrong = invoke(
        &live_args(&live, &["--output", "json", "login", "--username", USER]),
        "wrong\n",
        &send_request,
    )?;
    let error: Value = serde_json::from_str(&json_wrong.err)?;
    assert!(error
        .get("error")
        .and_then(Value::as_str)
        .is_some_and(|text| text.contains("invalid_credentials")));
    assert_eq!(json_wrong.out, "");

    Ok(())
}


#[test]
fn http_client_rules() -> TestResult {
    let live = start_live()?;
    let health = HttpRequest {
        method: HttpMethod::Get,
        url: format!("{}/health", live.url),
        token: None,
        body: String::new(),
    };
    let reply = send_request(Some(&live.ca_file), &health)?;
    assert_eq!(reply.status, STATUS_OK);
    assert!(reply.body.contains("ok"));

    assert!(send_request(None, &health).is_err());
    let plain = HttpRequest {
        url: health.url.replacen("https://", "http://", 1),
        ..health.clone()
    };
    assert!(send_request(Some(&live.ca_file), &plain).is_err());
    let invalid = HttpRequest {
        url: "https://exa mple".to_owned(),
        ..health.clone()
    };
    assert!(send_request(Some(&live.ca_file), &invalid).is_err());
    let closed = HttpRequest {
        url: "https://localhost:1/".to_owned(),
        ..health.clone()
    };
    assert!(send_request(Some(&live.ca_file), &closed).is_err());

    assert!(build_agent(None).is_ok());
    let dir = tempdir()?;
    let missing = build_agent(Some(&dir.path().join("absent.pem")));
    assert!(matches!(missing, Err(ClientError::CaFile { .. })));
    let garbage = dir.path().join("garbage.pem");
    fs::write(&garbage, "not a certificate")?;
    assert!(build_agent(Some(&garbage)).is_err());
    Ok(())
}


#[test]
fn session_file_rules() -> TestResult {
    let dir = tempdir()?;
    let path = session_path(&dir.path().join("nested"));
    assert!(matches!(load_session(&path), Err(CliError::NotLoggedIn)));
    remove_session(&path)?;

    let session = Session {
        server: FAKE_SERVER.to_owned(),
        token: "secret-token".to_owned(),
    };
    save_session(&path, &session)?;
    assert_eq!(mode_of(&path)?, OWNER_ONLY);
    set_mode(&path, WORLD_READABLE)?;
    save_session(&path, &session)?;
    assert_eq!(mode_of(&path)?, OWNER_ONLY);
    let loaded = load_session(&path)?;
    assert_eq!(loaded.token, "secret-token");
    assert_eq!(loaded.server, FAKE_SERVER);

    fs::write(&path, "{broken")?;
    assert!(matches!(load_session(&path), Err(CliError::SessionFormat { .. })));
    remove_session(&path)?;
    assert!(!path.exists());

    let directory = dir.path().join("as-directory");
    fs::create_dir_all(directory.join("inner"))?;
    assert!(matches!(load_session(&directory), Err(CliError::Session { .. })));
    assert!(matches!(remove_session(&directory), Err(CliError::Session { .. })));

    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "file")?;
    assert!(matches!(save_session(&session_path(&blocker), &session), Err(CliError::Session { .. })));
    Ok(())
}


#[test]
fn server_address_rules() -> TestResult {
    let dir = tempdir()?;
    let send = fixed(STATUS_OK, "{}");
    let context = |server| Context {
        server,
        ca_file: None,
        session_file: session_path(dir.path()),
        send: &send,
    };
    assert!(matches!(server_address(&context(None), None), Err(CliError::NoServer)));
    assert!(matches!(server_address(&context(Some("http://x")), None), Err(CliError::InsecureServer)));
    assert_eq!(server_address(&context(Some("https://x/")), None)?, "https://x");
    let stored = Session {
        server: "https://stored".to_owned(),
        token: String::new(),
    };
    assert_eq!(server_address(&context(None), Some(&stored))?, "https://stored");
    assert_eq!(server_address(&context(Some("https://given")), Some(&stored))?, "https://given");
    Ok(())
}


#[test]
fn injected_replies_are_classified() -> TestResult {
    let dir = tempdir()?;
    let login = offline_args(dir.path(), &["--server", FAKE_SERVER, "login", "--username", USER]);

    let refused = invoke(
        &login,
        "pw\n",
        &fixed(STATUS_ERROR, "{\"error\":{\"code\":\"boom\",\"message\":\"bad\"}}"),
    )?;
    assert_eq!(refused.code, FAILURE);
    assert!(refused.err.contains("(500): boom: bad"));

    let garbled = invoke(&login, "pw\n", &fixed(STATUS_ERROR, "oops"))?;
    assert!(garbled.err.contains("unexpected reply from the server (status 500)"));

    let no_token = invoke(&login, "pw\n", &fixed(STATUS_OK, "{}"))?;
    assert!(no_token.err.contains("unexpected reply"));

    let failing = |_: Option<&Path>, _: &HttpRequest| -> Result<HttpReply, ClientError> {
        Err(ClientError::CaFile {
            path: "x".into(),
            source: std::io::Error::other("down"),
        })
    };
    let down = invoke(&login, "pw\n", &failing)?;
    assert!(down.err.contains("cannot read the CA file"));

    let no_server = invoke(&offline_args(dir.path(), &["login", "--username", USER]), "pw\n", &fixed(STATUS_OK, "{}"))?;
    assert!(no_server.err.contains("no server address"));

    let insecure = invoke(
        &offline_args(dir.path(), &["--server", "http://x", "login", "--username", USER]),
        "pw\n",
        &fixed(STATUS_OK, "{}"),
    )?;
    assert!(insecure.err.contains("https://"));

    let saved = invoke(&login, "pw\n", &fixed(STATUS_OK, "{\"token\":\"t1\",\"token_type\":\"Bearer\"}"))?;
    assert_eq!(saved.code, SUCCESS);
    assert_eq!(saved.out, "logged in as reader\n");
    assert_eq!(load_session(&session_path(dir.path()))?.token, "t1");

    let bad_me = invoke(&offline_args(dir.path(), &["whoami"]), "", &fixed(STATUS_OK, "[]"))?;
    assert!(bad_me.err.contains("unexpected reply"));

    let blocked = tempdir()?;
    let blocker = blocked.path().join("file");
    fs::write(&blocker, "x")?;
    let unsaved = invoke(
        &offline_args(&blocker, &["--server", FAKE_SERVER, "login", "--username", USER]),
        "pw\n",
        &fixed(STATUS_OK, "{\"token\":\"t\"}"),
    )?;
    assert_eq!(unsaved.code, FAILURE);

    let unreadable = run_reporting(
        &login,
        None,
        &fixed(STATUS_OK, "{}"),
        &mut broken_input(),
        &mut Vec::new(),
        &mut Vec::new(),
    )?;
    assert_eq!(format!("{unreadable:?}"), FAILURE);
    Ok(())
}


#[test]
fn logout_always_forgets_the_session() -> TestResult {
    let dir = tempdir()?;
    let args = offline_args(dir.path(), &["logout"]);
    let missing = invoke(&args, "", &fixed(STATUS_OK, ""))?;
    assert!(missing.err.contains("not logged in"));

    store_session(dir.path())?;
    let failed = invoke(&args, "", &fixed(STATUS_ERROR, "{\"error\":{\"code\":\"expired\",\"message\":\"gone\"}}"))?;
    assert_eq!(failed.code, FAILURE);
    assert!(!session_path(dir.path()).exists());

    store_session(dir.path())?;
    let done = invoke(&args, "", &fixed(STATUS_OK, ""))?;
    assert_eq!(done.out, "logged out\n");
    let json = {
        store_session(dir.path())?;
        invoke(&offline_args(dir.path(), &["--output", "json", "logout"]), "", &fixed(STATUS_OK, ""))?
    };
    assert_eq!(json.out, "{\"logged_out\":true}\n");
    Ok(())
}


#[test]
fn config_validate_checks_every_yaml_file() -> TestResult {
    let dir = tempdir()?;
    let root = dir.path();
    fs::write(root.join("platform.yaml"), PLATFORM_OK)?;
    fs::write(root.join("siem.yaml"), MODULE_OK)?;
    fs::write(root.join("other.yml"), MODULE_OK)?;
    fs::write(root.join("notes.txt"), "ignored")?;
    fs::write(root.join("noextension"), "ignored")?;
    fs::create_dir_all(root.join("folder.yaml"))?;
    let send = fixed(STATUS_OK, "");
    let args = offline_args(root, &["config", "validate", &root.display().to_string()]);
    let ok = invoke(&args, "", &send)?;
    assert_eq!(ok.code, SUCCESS, "{}", ok.err);
    assert_eq!(ok.out.lines().count(), CHANGES);
    assert!(ok.out.contains("ok ") && ok.out.contains("platform.yaml"));

    let json = invoke(
        &offline_args(root, &["--output", "json", "config", "validate", &root.display().to_string()]),
        "",
        &send,
    )?;
    let parsed: Value = serde_json::from_str(&json.out)?;
    assert_eq!(parsed.get("validated").and_then(Value::as_array).map(Vec::len), Some(CHANGES));

    fs::write(root.join("bad.yaml"), MODULE_BAD)?;
    let bad = invoke(&args, "", &send)?;
    assert_eq!(bad.code, FAILURE);
    assert!(bad.err.contains("bad.yaml"));

    let missing = invoke(
        &offline_args(root, &["config", "validate", &root.join("absent").display().to_string()]),
        "",
        &send,
    )?;
    assert_eq!(missing.code, FAILURE);
    assert!(yaml_files(&root.join("absent")).is_err());
    assert!(is_yaml(Path::new("a.yaml")) && is_yaml(Path::new("a.yml")));
    assert!(!is_yaml(Path::new("a.txt")) && !is_yaml(Path::new("a")));
    Ok(())
}


#[test]
fn plan_and_apply_input_errors() -> TestResult {
    let dir = tempdir()?;
    let root = dir.path();
    let desired = root.join("desired");
    let state = root.join("state");
    fs::create_dir_all(&desired)?;
    fs::create_dir_all(&state)?;
    fs::write(desired.join("a"), "1")?;
    let desired_text = desired.display().to_string();
    let state_text = state.display().to_string();
    let absent = root.join("absent").display().to_string();
    let send = fixed(STATUS_OK, "{\"username\":\"reader\",\"roles\":[],\"mfa_enrolled\":false}");

    let no_state = invoke(&offline_args(root, &["plan", &desired_text, "--state", &absent]), "", &send)?;
    assert_eq!(no_state.code, FAILURE);
    let no_desired = invoke(&offline_args(root, &["plan", &absent, "--state", &state_text]), "", &send)?;
    assert_eq!(no_desired.code, FAILURE);

    let audit = root.join("audit.log").display().to_string();
    let flags = ["--audit-file", &audit, "--justification", "j"];
    let mut apply = vec!["apply", &desired_text, "--state", &state_text];
    apply.extend(flags);

    let anonymous = invoke(&offline_args(root, &apply), "y\n", &send)?;
    assert!(anonymous.err.contains("not logged in"));

    store_session(root)?;
    let unread = run_reporting(
        &offline_args(root, &apply),
        None,
        &send,
        &mut broken_input(),
        &mut Vec::new(),
        &mut Vec::new(),
    )?;
    assert_eq!(format!("{unread:?}"), FAILURE);

    let prompt_failed = execute(
        &Cli::try_parse_from(offline_args(root, &apply))?,
        None,
        &send,
        &mut "y\n".as_bytes(),
        &mut BrokenOutput { fail_write: true },
    );
    assert!(matches!(prompt_failed, Err(CliError::Output(_))));
    let flush_failed = execute(
        &Cli::try_parse_from(offline_args(root, &apply))?,
        None,
        &send,
        &mut "y\n".as_bytes(),
        &mut BrokenOutput { fail_write: false },
    );
    assert!(matches!(flush_failed, Err(CliError::Output(_))));

    let bad_audit_dir = root.join("missing-dir").join("audit.log").display().to_string();
    let bad_audit = invoke(
        &offline_args(
            root,
            &[
                "apply",
                &desired_text,
                "--state",
                &state_text,
                "--audit-file",
                &bad_audit_dir,
                "--justification",
                "j",
                "--yes",
            ],
        ),
        "",
        &send,
    )?;
    assert_eq!(bad_audit.code, FAILURE);

    let nothing_to_do = root.join("same");
    fs::create_dir_all(&nothing_to_do)?;
    let same = invoke(
        &offline_args(
            root,
            &[
                "apply",
                &nothing_to_do.display().to_string(),
                "--state",
                &nothing_to_do.display().to_string(),
                "--audit-file",
                &audit,
                "--justification",
                "j",
                "--yes",
            ],
        ),
        "",
        &send,
    )?;
    assert_eq!(same.out, "applied 0\n");

    #[cfg(unix)]
    {
        set_mode(&state, READ_ONLY)?;
        let failing = invoke(&offline_args(root, &[&apply[..], &["--yes"]].concat()), "", &send)?;
        set_mode(&state, FULL_OWNER)?;
        assert_eq!(failing.code, FAILURE);
    }
    Ok(())
}


#[test]
fn audit_verify_reports_missing_file() -> TestResult {
    let dir = tempdir()?;
    let outcome = invoke(
        &offline_args(dir.path(), &["audit", "verify", &dir.path().join("absent.log").display().to_string()]),
        "",
        &fixed(STATUS_OK, ""),
    )?;
    assert_eq!(outcome.code, FAILURE);
    Ok(())
}


#[test]
fn default_config_directory_and_usage() -> TestResult {
    let dir = tempdir()?;
    let send = fixed(STATUS_OK, "");
    let no_dir = {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_reporting(&words(&["xdrctl", "whoami"]), None, &send, &mut "".as_bytes(), &mut out, &mut err)?;
        (format!("{code:?}"), String::from_utf8(err)?)
    };
    assert_eq!(no_dir.0, FAILURE);
    assert!(no_dir.1.contains("no user configuration directory"));

    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_reporting(
        &words(&["xdrctl", "whoami"]),
        Some(dir.path().to_path_buf()),
        &send,
        &mut "".as_bytes(),
        &mut out,
        &mut err,
    )?;
    assert_eq!(format!("{code:?}"), FAILURE);
    assert!(String::from_utf8(err)?.contains("not logged in"));

    let usage = invoke(&words(&["xdrctl", "bogus"]), "", &send)?;
    assert_eq!(usage.code, USAGE_FAILURE);
    assert!(usage.err.contains("Usage"));
    assert_eq!(usage.out, "");

    let help = invoke(&words(&["xdrctl", "--help"]), "", &send)?;
    assert_eq!(help.code, SUCCESS);
    assert!(help.out.contains("login") && help.out.contains("audit"));
    Ok(())
}


#[test]
fn rendering_reports_write_failures() -> TestResult {
    let report = Report {
        text: "hello".to_owned(),
        json: serde_json::json!({"a": 1}),
    };
    let mut text = Vec::new();
    render(OutputFormat::Text, &report, &mut text)?;
    assert_eq!(String::from_utf8(text)?, "hello\n");
    let mut json = Vec::new();
    render(OutputFormat::Json, &report, &mut json)?;
    assert_eq!(String::from_utf8(json)?, "{\"a\":1}\n");
    assert!(render(OutputFormat::Text, &report, &mut BrokenOutput { fail_write: true }).is_err());

    let error = CliError::NotLoggedIn;
    let mut shown = Vec::new();
    render_error(OutputFormat::Text, &error, &mut shown)?;
    assert_eq!(String::from_utf8(shown)?, "error: not logged in: run `xdrctl login`\n");
    assert!(render_error(OutputFormat::Json, &error, &mut BrokenOutput { fail_write: true }).is_err());

    let dir = tempdir()?;
    let send: &SendFn = &fixed(STATUS_OK, "");
    let args = offline_args(dir.path(), &["whoami"]);
    let broken = run_reporting(
        &args,
        None,
        send,
        &mut "".as_bytes(),
        &mut Vec::new(),
        &mut BrokenOutput { fail_write: true },
    );
    assert!(broken.is_err());
    let usage_broken = run_reporting(
        &words(&["xdrctl", "bogus"]),
        None,
        send,
        &mut "".as_bytes(),
        &mut Vec::new(),
        &mut BrokenOutput { fail_write: true },
    );
    assert!(usage_broken.is_err());
    let help_broken = run_reporting(
        &words(&["xdrctl", "--help"]),
        None,
        send,
        &mut "".as_bytes(),
        &mut BrokenOutput { fail_write: true },
        &mut Vec::new(),
    );
    assert!(help_broken.is_err());
    Ok(())
}


const EXTRA_CHARS: usize = 10;


const MAX_DIFF_CHARS_EXTRA: usize = 50_000;


#[test]
fn audit_declared_keys_kept_undeclared_redacted_and_long_values_cut() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = core_audit::log::open_file_log(&path)?;
    let context = core_config::apply::ApplyContext {
        actor: core_audit::model::Actor {
            kind: core_audit::model::ActorKind::User,
            id: "reader".to_owned(),
        },
        tenant: "default".to_owned(),
        module: "xdrctl".to_owned(),
        request_id: "r".to_owned(),
        justification: "j".to_owned(),
    };
    let change = core_config::plan::Change {
        kind: core_config::plan::ChangeKind::Update,
        key: "k".to_owned(),
        before: String::new(),
        after: String::new(),
        diff: "d".to_owned(),
    };
    let mut entry = core_config::apply::audit_entry(&context, &change);
    entry.parameters.insert("password".to_owned(), "hunter2-secret".to_owned());
    entry
        .parameters
        .insert("diff_sha256".to_owned(), "x".repeat(core_config::reload::MAX_VALUE_CHARS + EXTRA_CHARS));
    let record = xdrctl::commands::append_apply_entry(&log, entry)?;
    assert_eq!(xdrctl::commands::XDRCTL_DECLARED_KEYS, core_config::apply::APPLY_DECLARED_KEYS);
    assert_eq!(record.parameters.get("password").map(String::as_str), Some("[REDACTED]"));
    assert_eq!(record.parameters.get("diff").map(String::as_str), Some("d"));
    assert!(record
        .parameters
        .get("diff_sha256")
        .is_some_and(|value| value.contains("10 characters omitted")));
    assert!(!fs::read_to_string(&path)?.contains("hunter2-secret"));
    Ok(())
}


#[test]
fn audit_diff_cut_once_and_target_and_justification_bounded() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = core_audit::log::open_file_log(&path)?;
    let context = core_config::apply::ApplyContext {
        actor: core_audit::model::Actor {
            kind: core_audit::model::ActorKind::User,
            id: "reader".to_owned(),
        },
        tenant: "default".to_owned(),
        module: "xdrctl".to_owned(),
        request_id: "r".to_owned(),
        justification: "j".repeat(core_config::reload::MAX_VALUE_CHARS + EXTRA_CHARS),
    };
    let change = core_config::plan::Change {
        kind: core_config::plan::ChangeKind::Update,
        key: "k".repeat(core_config::reload::MAX_VALUE_CHARS + EXTRA_CHARS),
        before: String::new(),
        after: String::new(),
        diff: "d".repeat(core_config::reload::MAX_DIFF_CHARS + MAX_DIFF_CHARS_EXTRA),
    };
    let entry = core_config::apply::audit_entry(&context, &change);
    let expected = entry.parameters.get("diff").cloned();
    let record = xdrctl::commands::append_apply_entry(&log, entry)?;
    assert_eq!(record.parameters.get("diff"), expected.as_ref());
    assert!(expected.is_some_and(|value| value.ends_with(&format!("[diff truncated, {} characters omitted]", MAX_DIFF_CHARS_EXTRA))));
    assert!(record.target.contains("10 characters omitted"));
    assert!(record.justification.is_some_and(|value| value.contains("10 characters omitted")));
    Ok(())
}


const STATUS_UNAUTHORIZED: u16 = 401;


const STATUS_FORBIDDEN: u16 = 403;


const STATUS_NOT_FOUND: u16 = 404;


const STATUS_TOO_MANY: u16 = 429;


const STATUS_BAD_REQUEST: u16 = 400;


const CASE_COUNT: usize = 5;


const SHOW_LINES: usize = 10;


const LIST_LINES: usize = 3;


const CURSOR_TOO_LONG: usize = 1025;


const THIRD_CALL: usize = 2;


const ALERTS_SERVER: &str = "https://example.test";


const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


const FIRST_PAGE: &str = "{\"items\":[{\"id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"rule_id\":\"r1\",\
\"rule_title\":\"Brute force\",\"severity\":\"high\",\"event_time\":\"2026-11-10T10:00:00Z\",\"created\":\"2026-11-10T10:00:01Z\",\
\"host_name\":\"srv1\",\"user_name\":null,\"event_ids\":[\"e1\",\"e2\"],\"summary\":{\"count\":3},\"summary_truncated\":false}],\
\"next_cursor\":\"abc_-=\"}";


const LAST_PAGE: &str = "{\"items\":[],\"next_cursor\":null}";


const HOSTILE: &str = "{\"id\":\"ab\\u001b[2Jcd\",\"rule_id\":\"r\\u0007\",\"rule_title\":\"t\\u001b]0;x\\u0007\\n\\u202eevil\",\
\"severity\":\"low\",\"event_time\":\"2026\",\"created\":\"2026\",\"host_name\":\"h\\r\",\"user_name\":\"u\\u0000\",\
\"event_ids\":[\"e\\u001b\"],\"summary\":{\"k\":\"v\\u001b\"},\"summary_truncated\":true}";


fn store_alerts_session(dir: &Path) -> TestResult {
    save_session(
        &session_path(dir),
        &Session {
            server: ALERTS_SERVER.to_owned(),
            token: "tok".to_owned(),
        },
    )?;
    Ok(())
}


fn alerts_stub<'a>(
    seen: &'a RefCell<Vec<String>>,
    status: u16,
    body: &'static str,
) -> impl Fn(Option<&Path>, &HttpRequest) -> Result<HttpReply, ClientError> + 'a {
    move |_, request| {
        seen.borrow_mut().push(format!("{} {:?}", request.url, request.token));
        Ok(HttpReply {
            status,
            body: body.to_owned(),
        })
    }
}


#[test]
fn list_prints_a_table_and_the_cursor() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let first = invoke(
        &offline_args(dir.path(), &["alerts", "list", "--limit", "5", "--cursor", "c1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, FIRST_PAGE),
    )?;
    assert_eq!(first.code, SUCCESS);
    assert!(first.out.contains("0123456789ab\thigh\tBrute force\tsrv1\t-\t2026-11-10T10:00:00Z"));
    assert!(first.out.ends_with("next cursor: abc_-=\n"));
    assert_eq!(
        seen.borrow().first().map(String::as_str),
        Some("https://example.test/alerts?limit=5&cursor=c1 Some(\"tok\")")
    );

    let last = invoke(
        &offline_args(dir.path(), &["alerts", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert!(last.out.ends_with("no more alerts\n"));
    assert_eq!(
        seen.borrow().get(1).map(String::as_str),
        Some("https://example.test/alerts Some(\"tok\")")
    );

    let only_cursor = invoke(
        &offline_args(dir.path(), &["alerts", "list", "--cursor", "c2"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert_eq!(only_cursor.code, SUCCESS);
    assert_eq!(
        seen.borrow().get(THIRD_CALL).map(String::as_str),
        Some("https://example.test/alerts?cursor=c2 Some(\"tok\")")
    );
    Ok(())
}


#[test]
fn json_output_is_the_api_body() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let listed = invoke(
        &offline_args(dir.path(), &["--output", "json", "alerts", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, FIRST_PAGE),
    )?;
    assert_eq!(serde_json::from_str::<Value>(&listed.out)?, serde_json::from_str::<Value>(FIRST_PAGE)?);
    Ok(())
}


#[test]
fn show_prints_every_field() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let first = serde_json::from_str::<Value>(FIRST_PAGE)?;
    let alert: &'static str = Box::leak(serde_json::to_string(first.get("items").and_then(|items| items.get(0)).ok_or("no item")?)?.into_boxed_str());
    let shown = invoke(
        &offline_args(dir.path(), &["alerts", "show", ID]),
        "",
        &alerts_stub(&seen, STATUS_OK, alert),
    )?;
    assert_eq!(shown.code, SUCCESS);
    assert!(shown.out.contains("rule: Brute force (r1)"));
    assert!(shown
        .out
        .contains("host: srv1\nuser: -\nevents: e1,e2\nsummary: {\"count\":3}\nsummary truncated: false"));
    assert_eq!(
        seen.borrow().first().map(String::as_str),
        Some(format!("https://example.test/alerts/{ID} Some(\"tok\")").as_str())
    );
    Ok(())
}


#[test]
fn hostile_values_are_escaped() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let shown = invoke(
        &offline_args(dir.path(), &["alerts", "show", ID]),
        "",
        &alerts_stub(&seen, STATUS_OK, HOSTILE),
    )?;
    assert_eq!(shown.code, SUCCESS);
    assert!(!shown.out.contains('\u{1b}'));
    assert!(!shown.out.contains('\u{7}'));
    assert!(!shown.out.contains('\u{202e}'));
    assert!(!shown.out.contains('\r'));
    assert!(shown.out.contains("\\u{1b}"));
    assert_eq!(shown.out.lines().count(), SHOW_LINES);

    let page = format!("{{\"items\":[{HOSTILE}],\"next_cursor\":\"x\\u001b\"}}");
    let leaked: &'static str = Box::leak(page.into_boxed_str());
    let listed = invoke(&offline_args(dir.path(), &["alerts", "list"]), "", &alerts_stub(&seen, STATUS_OK, leaked))?;
    assert!(!listed.out.contains('\u{1b}'));
    assert_eq!(listed.out.lines().count(), LIST_LINES);
    Ok(())
}


#[test]
fn errors_map_without_the_raw_body() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let cases: [(u16, &'static str, &str); CASE_COUNT] = [
        (
            STATUS_UNAUTHORIZED,
            "{\"error\":{\"code\":\"unauthorized\",\"message\":\"SECRET-A\"}}",
            "run `xdrctl login`",
        ),
        (
            STATUS_FORBIDDEN,
            "{\"error\":{\"code\":\"forbidden\",\"message\":\"SECRET-B\"}}",
            "permission denied",
        ),
        (
            STATUS_NOT_FOUND,
            "{\"error\":{\"code\":\"not_found\",\"message\":\"SECRET-C\"}}",
            "not found",
        ),
        (STATUS_TOO_MANY, "{\"error\":{\"code\":\"rate\",\"message\":\"SECRET-D\"}}", "retry later"),
        (
            STATUS_BAD_REQUEST,
            "{\"error\":{\"code\":\"bad\",\"message\":\"cursor\\u001b\"}}",
            "(400): bad: cursor\\u{1b}",
        ),
    ];
    for (status, body, expected) in cases {
        let list = invoke(&offline_args(dir.path(), &["alerts", "list"]), "", &alerts_stub(&seen, status, body))?;
        assert_eq!(list.code, FAILURE);
        assert!(list.err.contains(expected), "{}", list.err);
        assert!(!list.err.contains("SECRET"));
        let show = invoke(&offline_args(dir.path(), &["alerts", "show", ID]), "", &alerts_stub(&seen, status, body))?;
        assert!(show.err.contains(expected), "{}", show.err);
    }
    let garbled = invoke(
        &offline_args(dir.path(), &["alerts", "list"]),
        "",
        &alerts_stub(&seen, STATUS_ERROR, "<html>raw</html>"),
    )?;
    assert!(garbled.err.contains("unexpected reply"));
    assert!(!garbled.err.contains("raw"));
    let bad_list = invoke(&offline_args(dir.path(), &["alerts", "list"]), "", &alerts_stub(&seen, STATUS_OK, "[]"))?;
    assert!(bad_list.err.contains("unexpected reply"));
    let bad_show = invoke(
        &offline_args(dir.path(), &["alerts", "show", ID]),
        "",
        &alerts_stub(&seen, STATUS_OK, "[]"),
    )?;
    assert!(bad_show.err.contains("unexpected reply"));
    let json_error = invoke(
        &offline_args(dir.path(), &["--output", "json", "alerts", "list"]),
        "",
        &alerts_stub(&seen, STATUS_FORBIDDEN, "{\"error\":{\"code\":\"f\",\"message\":\"m\"}}"),
    )?;
    assert!(json_error.err.contains("permission denied"));
    Ok(())
}


#[test]
fn bad_arguments_and_missing_session_never_reach_the_server() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    for args in [
        ["alerts", "show", "../x"],
        ["alerts", "show", "zz"],
        ["alerts", "list", "--cursor=a&tenant=b"],
    ] {
        let outcome = invoke(&offline_args(dir.path(), &args), "", &alerts_stub(&seen, STATUS_OK, LAST_PAGE))?;
        assert_eq!(outcome.code, FAILURE);
        assert!(outcome.err.contains("invalid"));
    }
    let empty = invoke(
        &offline_args(dir.path(), &["alerts", "show", ""]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert_eq!(empty.code, FAILURE);
    for limit in ["0", "101", "x"] {
        let outcome = invoke(
            &offline_args(dir.path(), &["alerts", "list", "--limit", limit]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, USAGE_FAILURE);
    }
    assert!(seen.borrow().is_empty());
    let fresh = tempdir()?;
    let unauthenticated = invoke(
        &offline_args(fresh.path(), &["alerts", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert!(unauthenticated.err.contains("not logged in"));
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[test]
fn helpers_validate_and_map() -> TestResult {
    assert!(valid_id(ID));
    assert!(!valid_id(&format!("{ID}0")));
    assert!(valid_cursor("-a_B=9"));
    assert!(!valid_cursor(&"a".repeat(CURSOR_TOO_LONG)));
    assert!(!valid_cursor("a b"));
    assert!(!valid_cursor(""));
    assert!(list_path(None, Some("a b")).is_err());
    assert_eq!(list_path(Some(1), None)?, "/alerts?limit=1");
    assert!(matches!(map_status(CliError::NotLoggedIn), CliError::NotLoggedIn));
    Ok(())
}


const CASE_SUMMARY: &str = "\"id\":\"INC-2026-0001-extra\",\"title\":\"Phish\",\"severity\":\"high\",\"status\":\"in_progress\",\"assignee\":null,\
\"case_type\":\"phishing\",\"created_at\":1762857600,\"updated_at\":99999999999999,\"version\":3,\
\"counts\":{\"tasks\":1,\"observables\":2,\"comments\":3,\"history\":4,\"alerts\":5}";


const HOSTILE_CASE: &str = "\"id\":\"c\\u001b1\",\"title\":\"t\\u001b]0;pwned\\u0007\\u202eevil\",\"severity\":\"low\",\"status\":\"new\",\
\"assignee\":\"a\\u001b\",\"case_type\":null,\"created_at\":0,\"updated_at\":1,\"version\":1,\
\"counts\":{\"tasks\":0,\"observables\":0,\"comments\":0,\"history\":0,\"alerts\":0}";


const CASE_ID_REFUSED: [&str; 8] = ["../alerts", "x?tenant=b", "%2e%2e", "x#y", "a/b", ".hidden", "-x", ""];


const CASE_ID_LONG: usize = 129;


const CASE_ID_FIRST_TIME: &str = "1970-01-01T00:00:01Z";


#[test]
fn cases_list_paths_and_text() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let page: &'static str = Box::leak(format!("{{\"items\":[{{{CASE_SUMMARY}}}],\"next_cursor\":\"abc_-=\"}}").into_boxed_str());
    let first = invoke(
        &offline_args(dir.path(), &["cases", "list", "--limit", "5", "--cursor", "c1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, page),
    )?;
    assert_eq!(first.code, SUCCESS);
    assert!(first.out.contains("INC-2026-000\thigh\tin_progress\tPhish\t-\t-\n"));
    assert!(first.out.ends_with("next cursor: abc_-=\n"));
    let last = invoke(
        &offline_args(dir.path(), &["cases", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert!(last.out.ends_with("no more cases\n"));
    let plain = invoke(
        &offline_args(dir.path(), &["cases", "list", "--cursor", "c2"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert_eq!(plain.code, SUCCESS);
    let urls = seen.borrow().clone();
    assert_eq!(
        urls,
        vec![
            "https://example.test/cases?limit=5&cursor=c1 Some(\"tok\")",
            "https://example.test/cases Some(\"tok\")",
            "https://example.test/cases?cursor=c2 Some(\"tok\")",
        ]
    );
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "cases", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, page),
    )?;
    assert_eq!(serde_json::from_str::<Value>(json.out.trim())?, serde_json::from_str::<Value>(page)?);
    Ok(())
}


#[test]
fn cases_show_prints_every_field() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body: &'static str = Box::leak(
        format!(
            "{{{CASE_SUMMARY},\"description\":\"d\\u001b\",\"resolution\":\"benign\",\"template\":null,\
             \"tasks\":[{{\"title\":\"t\\u202e\",\"status\":\"todo\",\"due\":null,\"log\":[]}}]}}"
        )
        .into_boxed_str(),
    );
    let shown = invoke(
        &offline_args(dir.path(), &["cases", "show", "INC-2026-0001.a_b"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert_eq!(shown.code, SUCCESS);
    assert!(shown.out.contains("created: 2025-11-11T10:40:00Z\n"));
    assert!(shown.out.contains("updated: -\n"));
    assert!(shown.out.contains("counts: tasks 1 observables 2 comments 3 history 4 alerts 5\n"));
    assert!(shown.out.contains("description: d\\u{1b}\n"));
    assert!(shown.out.contains("resolution: benign\n"));
    assert!(shown.out.contains("template: -\n"));
    assert!(shown.out.contains("task: t\\u{202e} (todo)"));
    assert_eq!(
        seen.borrow().first().map(String::as_str),
        Some("https://example.test/cases/INC-2026-0001.a_b Some(\"tok\")")
    );
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "cases", "show", "x"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert_eq!(serde_json::from_str::<Value>(json.out.trim())?, serde_json::from_str::<Value>(body)?);
    assert_eq!(xdrctl::cases::format_time(1), CASE_ID_FIRST_TIME);
    Ok(())
}


#[test]
fn cases_hostile_values_are_escaped() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let page: &'static str = Box::leak(format!("{{\"items\":[{{{HOSTILE_CASE}}}],\"next_cursor\":\"x\\u001b\"}}").into_boxed_str());
    let listed = invoke(&offline_args(dir.path(), &["cases", "list"]), "", &alerts_stub(&seen, STATUS_OK, page))?;
    let detail: &'static str =
        Box::leak(format!("{{{HOSTILE_CASE},\"description\":null,\"resolution\":null,\"template\":null,\"tasks\":[]}}").into_boxed_str());
    let shown = invoke(
        &offline_args(dir.path(), &["cases", "show", "c1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, detail),
    )?;
    for text in [&listed.out, &shown.out] {
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{7}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("\\u{1b}]0;pwned\\u{7}\\u{202e}evil"));
    }
    Ok(())
}


#[test]
fn cases_bad_ids_and_cursors_make_no_request() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let long = "a".repeat(CASE_ID_LONG);
    for id in CASE_ID_REFUSED.iter().copied().chain(std::iter::once(long.as_str())) {
        let outcome = invoke(
            &offline_args(dir.path(), &["cases", "show", "--", id]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, FAILURE);
        assert!(outcome.err.contains("invalid case id"));
    }
    let cursor = invoke(
        &offline_args(dir.path(), &["cases", "list", "--cursor=a&tenant=b"]),
        "",
        &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
    )?;
    assert_eq!(cursor.code, FAILURE);
    for limit in ["0", "101"] {
        let outcome = invoke(
            &offline_args(dir.path(), &["cases", "list", "--limit", limit]),
            "",
            &alerts_stub(&seen, STATUS_OK, LAST_PAGE),
        )?;
        assert_eq!(outcome.code, USAGE_FAILURE);
    }
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[test]
fn cases_errors_map_without_the_raw_body() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body = "{\"error\":{\"code\":\"c\\u001b\",\"message\":\"SECRET\"}}";
    for (status, expected) in [
        (STATUS_UNAUTHORIZED, "not valid"),
        (STATUS_FORBIDDEN, "permission denied"),
        (STATUS_NOT_FOUND, "not found"),
        (STATUS_TOO_MANY, "too many"),
    ] {
        for args in [vec!["cases", "list"], vec!["cases", "show", "c1"]] {
            let outcome = invoke(&offline_args(dir.path(), &args), "", &alerts_stub(&seen, status, body))?;
            assert!(outcome.err.contains(expected));
            assert!(!outcome.err.contains("SECRET"));
        }
    }
    let other = invoke(&offline_args(dir.path(), &["cases", "list"]), "", &alerts_stub(&seen, STATUS_ERROR, body))?;
    assert!(other.err.contains("c\\u{1b}"));
    assert!(!other.err.contains('\u{1b}'));
    let raw = invoke(
        &offline_args(dir.path(), &["cases", "list"]),
        "",
        &alerts_stub(&seen, STATUS_ERROR, "<html>raw</html>"),
    )?;
    assert!(!raw.err.contains("<html>"));
    let bad = invoke(
        &offline_args(dir.path(), &["cases", "list"]),
        "",
        &alerts_stub(&seen, STATUS_OK, "[SECRET]"),
    )?;
    assert!(bad.err.contains("unexpected reply"));
    assert!(!bad.err.contains("SECRET"));
    let bad_show = invoke(
        &offline_args(dir.path(), &["cases", "show", "c1"]),
        "",
        &alerts_stub(&seen, STATUS_OK, "[]"),
    )?;
    assert!(bad_show.err.contains("unexpected reply"));
    Ok(())
}


#[test]
fn case_id_grammar() -> TestResult {
    assert!(xdrctl::cases::valid_case_id("A0._-"));
    assert!(xdrctl::cases::valid_case_id(&"a".repeat(CASE_ID_LONG - 1)));
    assert!(!xdrctl::cases::valid_case_id(&"a".repeat(CASE_ID_LONG)));
    assert!(!xdrctl::cases::valid_case_id("_a"));
    assert!(!xdrctl::cases::valid_case_id("a b"));
    assert!(!xdrctl::cases::valid_case_id("é"));
    Ok(())
}


const HIDDEN_JSON: &str = "a\\u061c\\u202e\\u2066\\u200b\\ufeff\\u009b31m\\u007f\\u2028\\u2060\\u00adz";


const HIDDEN_ORIGINAL: &str = "a\u{061c}\u{202e}\u{2066}\u{200b}\u{feff}\u{9b}31m\u{7f}\u{2028}\u{2060}\u{ad}z";


const HIDDEN_CALLS: usize = 4;


const HIDDEN_RAW: [char; 10] = [
    '\u{061c}', '\u{202e}', '\u{2066}', '\u{200b}', '\u{feff}', '\u{9b}', '\u{7f}', '\u{2028}', '\u{2060}', '\u{ad}',
];


#[test]
fn hidden_characters_are_escaped_in_text_and_json() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let alert = format!(
        "{{\"id\":\"ab\",\"rule_id\":\"r\",\"rule_title\":\"{HIDDEN_JSON}\",\"severity\":\"low\",\"event_time\":\"2026\",\"created\":\"2026\",\
         \"host_name\":null,\"user_name\":null,\"event_ids\":[],\"summary\":{{}},\"summary_truncated\":false}}"
    );
    let case = format!(
        "\"id\":\"c1\",\"title\":\"{HIDDEN_JSON}\",\"severity\":\"low\",\"status\":\"new\",\"assignee\":null,\"case_type\":null,\
         \"created_at\":0,\"updated_at\":1,\"version\":1,\"counts\":{{\"tasks\":0,\"observables\":0,\"comments\":0,\"history\":0,\"alerts\":0}}"
    );
    let alert_page: &'static str = Box::leak(format!("{{\"items\":[{alert}],\"next_cursor\":null}}").into_boxed_str());
    let alert_body: &'static str = Box::leak(alert.into_boxed_str());
    let case_page: &'static str = Box::leak(format!("{{\"items\":[{{{case}}}],\"next_cursor\":null}}").into_boxed_str());
    let case_body: &'static str =
        Box::leak(format!("{{{case},\"description\":null,\"resolution\":null,\"template\":null,\"tasks\":[]}}").into_boxed_str());
    let calls: [(&[&str], &'static str); HIDDEN_CALLS] = [
        (&["alerts", "list"], alert_page),
        (&["alerts", "show", "ab"], alert_body),
        (&["cases", "list"], case_page),
        (&["cases", "show", "c1"], case_body),
    ];
    let original = HIDDEN_ORIGINAL;
    calls.iter().try_for_each(|(words, body)| -> TestResult {
        let text = invoke(&offline_args(dir.path(), words), "", &alerts_stub(&seen, STATUS_OK, body))?;
        let mut json_words = vec!["--output", "json"];
        json_words.extend(words.iter());
        let json = invoke(&offline_args(dir.path(), &json_words), "", &alerts_stub(&seen, STATUS_OK, body))?;
        HIDDEN_RAW.iter().for_each(|raw| {
            assert!(!text.out.contains(*raw));
            assert!(!json.out.contains(*raw));
        });
        assert!(json.out.contains("\\u202e"));
        let parsed: serde_json::Value = serde_json::from_str(&json.out)?;
        assert!(parsed.to_string().contains(original));
        Ok(())
    })
}


#[test]
fn hidden_characters_are_escaped_in_error_lines() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let seen = RefCell::new(Vec::new());
    let body: &'static str = Box::leak(format!("{{\"error\":{{\"code\":\"{HIDDEN_JSON}\",\"message\":\"{HIDDEN_JSON}\"}}}}").into_boxed_str());
    ["text", "json"].iter().try_for_each(|format| -> TestResult {
        let words = ["--output", format, "alerts", "list"];
        let outcome = invoke(&offline_args(dir.path(), &words), "", &alerts_stub(&seen, STATUS_ERROR, body))?;
        assert!(outcome.err.contains("u{ad}") || outcome.err.contains("u00ad"));
        HIDDEN_RAW.iter().for_each(|raw| assert!(!outcome.err.contains(*raw)));
        Ok(())
    })
}


#[test]
fn whoami_text_escapes_hidden_characters_and_backslashes() -> TestResult {
    let dir = tempdir()?;
    store_alerts_session(dir.path())?;
    let name = "a\\u001b[2J\\u202e\\u061c\\\\u{202e}\\u2028\\u009b";
    let body: &'static str = Box::leak(format!("{{\"username\":\"{name}\",\"roles\":[\"{name}\",\"r\"],\"mfa_enrolled\":true}}").into_boxed_str());
    let seen = RefCell::new(Vec::new());
    let text = invoke(&offline_args(dir.path(), &["whoami"]), "", &alerts_stub(&seen, STATUS_OK, body))?;
    HIDDEN_RAW.iter().for_each(|raw| assert!(!text.out.contains(*raw)));
    assert!(!text.out.contains('\u{1b}'));
    assert!(text.out.contains("\\\\u{202e}"));
    assert!(text.out.contains("a\\u{1b}[2J\\u{202e}\\u{61c}"));
    let json = invoke(
        &offline_args(dir.path(), &["--output", "json", "whoami"]),
        "",
        &alerts_stub(&seen, STATUS_OK, body),
    )?;
    assert!(!json.out.contains('\u{1b}'));
    assert!(json.out.contains("\\u202e"));
    Ok(())
}


#[test]
fn printable_marks_backslashes() -> TestResult {
    assert_eq!(xdrctl::alerts::printable("\\u{"), "\\\\u{");
    assert_eq!(xdrctl::alerts::printable("\u{202e}"), "\\u{202e}");
    Ok(())
}
