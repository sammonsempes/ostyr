mod support;


use clap::Parser;
use serde_json::Value;
use std::fs;
use std::path::Path;
use support::{
    broken_input, invoke, live_args, mode_of, offline_args, session_file, set_mode, start_live, words, BrokenOutput, Live, TestError, TestResult,
    OWNER_ONLY, PASSWORD, USER,
};
use tempfile::tempdir;
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
