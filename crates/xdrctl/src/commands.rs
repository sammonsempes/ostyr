use crate::error::CliError;
use crate::model::{ApplyArgs, Context, ErrorBody, HttpMethod, HttpRequest, LoginBody, LoginReply, MeReply, Report, Session};
use crate::session::{load_session, remove_session, save_session};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, open_file_log, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Record};
use core_audit::verify::verify;
use core_config::apply::{apply, ApplyContext, APPLY_DECLARED_KEYS};
use core_config::apply_cli::{apply_to_dir, read_state, write_plan};
use core_config::load::{load_module, load_platform};
use core_config::plan::{action_name, plan};
use core_config::reload::bounded_value;
use core_config::types::{BoxError, ConfigState, Plan};
use serde_json::json;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};


pub const FIRST_SUCCESS: u16 = 200;


pub const FIRST_REDIRECT: u16 = 300;


pub const HTTPS_PREFIX: &str = "https://";


pub const PLATFORM_FILE: &str = "platform.yaml";


pub const YAML_EXTENSIONS: [&str; 2] = ["yaml", "yml"];


pub const APPLY_TENANT: &str = "default";


pub const APPLY_MODULE: &str = "xdrctl";


pub const APPLY_REQUEST_ID: &str = "xdrctl-apply";


pub const CONFIRM_ANSWERS: [&str; 2] = ["y", "yes"];


pub fn server_address(ctx: &Context, stored: Option<&Session>) -> Result<String, CliError> {
    let chosen = ctx
        .server
        .or_else(|| stored.map(|session| session.server.as_str()))
        .ok_or(CliError::NoServer)?;
    if chosen.starts_with(HTTPS_PREFIX) {
        Ok(chosen.trim_end_matches('/').to_owned())
    } else {
        Err(CliError::InsecureServer)
    }
}


pub fn bad_reply(status: u16) -> impl FnOnce(serde_json::Error) -> CliError {
    move |source| CliError::BadReply { status, source }
}


pub fn refusal(status: u16, body: &str) -> CliError {
    match serde_json::from_str::<ErrorBody>(body) {
        Ok(parsed) => CliError::Refused {
            status,
            code: parsed.error.code,
            message: parsed.error.message,
        },
        Err(error) => bad_reply(status)(error),
    }
}


pub fn call(ctx: &Context, method: HttpMethod, server: &str, path: &str, token: Option<&str>, body: String) -> Result<String, CliError> {
    let request = HttpRequest {
        method,
        url: format!("{server}{path}"),
        token: token.map(str::to_owned),
        body,
    };
    let reply = (ctx.send)(ctx.ca_file, &request)?;
    if (FIRST_SUCCESS..FIRST_REDIRECT).contains(&reply.status) {
        Ok(reply.body)
    } else {
        Err(refusal(reply.status, &reply.body))
    }
}


pub fn call_with_session(ctx: &Context, method: HttpMethod, path: &str) -> Result<String, CliError> {
    let session = load_session(&ctx.session_file)?;
    let server = server_address(ctx, Some(&session))?;
    call(ctx, method, &server, path, Some(&session.token), String::new())
}


pub fn read_line(input: &mut dyn BufRead) -> Result<String, CliError> {
    let mut line = String::new();
    input.read_line(&mut line).map_err(CliError::Input)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}


/// Logs in with the password read from the first input line; only the session file receives the token.
pub fn login(ctx: &Context, username: &str, totp_code: Option<&str>, input: &mut dyn BufRead) -> Result<Report, CliError> {
    let server = server_address(ctx, None)?;
    let password = read_line(input)?;
    let body = serde_json::to_string(&LoginBody {
        username,
        password: &password,
        totp_code,
    })?;
    let reply = call(ctx, HttpMethod::Post, &server, "/auth/login", None, body)?;
    let parsed: LoginReply = serde_json::from_str(&reply).map_err(bad_reply(FIRST_SUCCESS))?;
    save_session(&ctx.session_file, &Session { server, token: parsed.token })?;
    Ok(Report {
        text: format!("logged in as {username}"),
        json: json!({ "username": username }),
    })
}


/// Revokes the session on the server and always deletes the local file, so an expired token cannot lock the user in.
pub fn logout(ctx: &Context) -> Result<Report, CliError> {
    let remote = call_with_session(ctx, HttpMethod::Post, "/auth/logout");
    remove_session(&ctx.session_file)?;
    remote.map(|_| Report {
        text: "logged out".to_owned(),
        json: json!({ "logged_out": true }),
    })
}


pub fn current_user(ctx: &Context) -> Result<MeReply, CliError> {
    let reply = call_with_session(ctx, HttpMethod::Get, "/auth/me")?;
    serde_json::from_str(&reply).map_err(bad_reply(FIRST_SUCCESS))
}


pub fn whoami(ctx: &Context) -> Result<Report, CliError> {
    let me = current_user(ctx)?;
    Ok(Report {
        text: format!("{} roles={} mfa={}", me.username, me.roles.join(","), me.mfa_enrolled),
        json: json!({ "username": me.username, "roles": me.roles, "mfa_enrolled": me.mfa_enrolled }),
    })
}


pub fn directory_error(path: &Path) -> impl FnOnce(std::io::Error) -> CliError + '_ {
    move |source| CliError::Directory {
        path: path.to_path_buf(),
        source,
    }
}


pub fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| YAML_EXTENSIONS.contains(&extension))
}


pub fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut files = fs::read_dir(dir)
        .and_then(|entries| entries.map(|entry| entry.map(|found| found.path())).collect::<std::io::Result<Vec<_>>>())
        .map_err(directory_error(dir))?;
    files.retain(|path| path.is_file() && is_yaml(path));
    files.sort();
    Ok(files)
}


pub fn validate_file(path: &Path) -> Result<String, CliError> {
    let name = path.display().to_string();
    if path.ends_with(PLATFORM_FILE) {
        load_platform(path).map(|_| name).map_err(CliError::from)
    } else {
        load_module(path).map(|_| name).map_err(CliError::from)
    }
}


pub fn config_validate(dir: &Path) -> Result<Report, CliError> {
    let names = yaml_files(dir)?.iter().map(|path| validate_file(path)).collect::<Result<Vec<_>, _>>()?;
    Ok(Report {
        text: names.iter().map(|name| format!("ok {name}")).collect::<Vec<_>>().join("\n"),
        json: json!({ "validated": names }),
    })
}


pub fn read_dir_state(dir: &Path) -> Result<ConfigState, CliError> {
    read_state(dir).map_err(directory_error(dir))
}


pub fn plan_json(changes: &Plan) -> serde_json::Value {
    changes
        .iter()
        .map(|change| json!({ "action": action_name(change.kind), "key": change.key, "diff": change.diff }))
        .collect()
}


pub fn plan_text(changes: &Plan) -> Result<String, CliError> {
    let mut buffer = Vec::new();
    write_plan(changes, &mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}


pub fn plan_command(desired: &Path, state: &Path) -> Result<Report, CliError> {
    let changes = plan(&read_dir_state(desired)?, &read_dir_state(state)?);
    Ok(Report {
        text: plan_text(&changes)?,
        json: plan_json(&changes),
    })
}


pub fn confirmed(changes: &Plan, input: &mut dyn BufRead, prompt: &mut dyn Write) -> Result<bool, CliError> {
    write!(prompt, "{}Apply {} change(s)? [y/N] ", plan_text(changes)?, changes.len())?;
    prompt.flush()?;
    let answer = read_line(input)?.trim().to_lowercase();
    Ok(CONFIRM_ANSWERS.contains(&answer.as_str()))
}


pub const XDRCTL_DECLARED_KEYS: [&str; 2] = APPLY_DECLARED_KEYS;


pub const ALREADY_BOUNDED_KEY: &str = "diff";


/// Appends with the declared keys only; `audit_entry` already cut the diff, so it is not cut again, and every other value, target and justification get a visible cut.
pub fn append_apply_entry<Output: Write>(log: &AuditLog<Output>, entry: NewEntry) -> Result<Record, AuditError> {
    let parameters = entry
        .parameters
        .iter()
        .map(|(key, value)| (key.clone(), keep_or_bound(key, value)))
        .collect();
    let target = bounded_value(&entry.target);
    let justification = entry.justification.as_deref().map(bounded_value);
    append_declared(
        log,
        NewEntry {
            parameters,
            target,
            justification,
            ..entry
        },
        &XDRCTL_DECLARED_KEYS,
    )
}


pub fn keep_or_bound(key: &str, value: &str) -> String {
    if key == ALREADY_BOUNDED_KEY {
        value.to_owned()
    } else {
        bounded_value(value)
    }
}


/// Applies the directory as the real state under the logged-in account; asks first unless `yes`.
pub fn apply_command(ctx: &Context, args: &ApplyArgs, input: &mut dyn BufRead, prompt: &mut dyn Write) -> Result<Report, CliError> {
    let me = current_user(ctx)?;
    let wanted = read_dir_state(&args.desired)?;
    let changes = plan(&wanted, &read_dir_state(&args.state)?);
    if !args.yes && !confirmed(&changes, input, prompt)? {
        Err(CliError::Cancelled)
    } else {
        let log = open_file_log(&args.audit_file)?;
        let context = ApplyContext {
            actor: Actor {
                kind: ActorKind::User,
                id: me.username,
            },
            tenant: APPLY_TENANT.to_owned(),
            module: APPLY_MODULE.to_owned(),
            request_id: APPLY_REQUEST_ID.to_owned(),
            justification: args.justification.clone(),
        };
        let report = apply(
            &changes,
            &wanted,
            &context,
            &mut |entry| append_apply_entry(&log, entry),
            &mut |change| apply_to_dir(&args.state, change).map_err(BoxError::from),
            &mut || read_state(&args.state).map_err(BoxError::from),
        )?;
        Ok(Report {
            text: format!("applied {}", report.applied.len()),
            json: json!({ "applied": report.applied }),
        })
    }
}


pub fn audit_verify(file: &Path) -> Result<Report, CliError> {
    let opened = File::open(file).map_err(directory_error(file))?;
    let report = verify(BufReader::new(opened), None)?;
    Ok(Report {
        text: format!("ok {} records head {}", report.records, report.head),
        json: json!({ "records": report.records, "head": report.head }),
    })
}
