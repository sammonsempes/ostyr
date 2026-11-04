use crate::error::AuthError;
use crate::model::CredentialInfo;
use crate::password::verify_password;
use crate::policy::load_compromised;
use crate::rbac::{builtin_catalog, load_catalog, PERMISSION_EVENTS_READ};
use crate::secretbox::KEY_BYTES;
use crate::service::{
    audit_name, authorize, bootstrap_administrator, change_roles, create_account, denial_reason, enrol_totp, login, record, revoke_all_sessions,
    revoke_token, Context, Denial, Enrolment, LoginRequest, State, ACTION_LOGIN, ACTION_SESSION_REVOKE, ANONYMOUS_ACTOR,
};
use crate::session::revoke_session;
use crate::store::{read_store_locked, update_store_file, Updated};
use crate::totp::{code_for_step, unix_seconds, TOTP_STEP_SECONDS};
use crate::types::{Clock, RandomFn, RoleCatalog, RoleSet, StoreKey};
use crate::webauthn::{
    build_webauthn, list_credentials, parse_webauthn_config, passkey_login_start, register_finish, register_start, remove_credential,
    rename_credential, webauthn_login_finish, webauthn_login_start, Assertion, RegistrationRequest,
};
use core_audit::log::{check_private, open_file_log};
use core_audit::model::Outcome;
use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use webauthn_rs::prelude::Webauthn;


pub const PATH_COUNT: usize = 4;


pub const KEY_READ_LIMIT: u64 = 33;


pub const CLI_TENANT: &str = "default";


pub const CLI_REQUEST_ID: &str = "cli";


pub const READ_ONLY_COMMANDS: [&str; 6] = ["totp", "check", "wa-list", "wa-register-start", "wa-login-start", "passkey-start"];


pub const USAGE: &str = "usage: auth_tool <store> <audit-log> <key-file> <compromised-list> [<webauthn-config> [<roles-file>]]; commands on stdin";


pub fn parse_roles(text: &str) -> RoleSet {
    text.split(',').filter(|role| !role.is_empty()).map(str::to_owned).collect()
}


pub fn totp_now(secret_text: &str, now: OffsetDateTime) -> Result<String, AuthError> {
    let secret = BASE32_NOPAD
        .decode(secret_text.as_bytes())
        .map_err(|error| AuthError::Usage(format!("secret is not base32: {error}")))?;
    Ok(code_for_step(&secret, unix_seconds(now)? / TOTP_STEP_SECONDS))
}


pub fn show_enrolment(enrolment: Enrolment) -> String {
    let codes: Vec<&str> = enrolment.backup_codes.iter().map(|code| code.expose_secret()).collect();
    format!("secret {}\nbackup {}", enrolment.secret.expose_secret(), codes.join(" "))
}


pub fn read_key_file(path: &str) -> Result<StoreKey, AuthError> {
    let file = File::open(path)?;
    check_private(&file).map_err(AuthError::KeyFile)?;
    let mut bytes = Vec::new();
    file.take(KEY_READ_LIMIT).read_to_end(&mut bytes)?;
    if bytes.len() == KEY_BYTES {
        Ok(SecretSlice::from(bytes))
    } else {
        Err(AuthError::InvalidKey)
    }
}


pub fn require_webauthn(webauthn: Option<&Webauthn>) -> Result<&Webauthn, AuthError> {
    webauthn.ok_or(AuthError::WebauthnNotConfigured)
}


pub fn json_text<Value: Serialize>(identifier: &str, value: &Value) -> Result<String, AuthError> {
    Ok(format!("ok {identifier} {}", serde_json::to_string(value)?))
}


pub fn show_credential(info: &CredentialInfo) -> String {
    let used = info.last_used.map_or_else(|| "-".to_owned(), |seconds| seconds.to_string());
    format!("{} {} {} {used}", info.id, info.name, info.created_at)
}


/// WebAuthn commands carry their JSON document as the last word(s); the rest of the line is rejoined with spaces.
pub fn execute_webauthn<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: Option<&Webauthn>,
    now: OffsetDateTime,
    words: &[&str],
) -> Result<String, AuthError> {
    match words {
        ["wa-register-start", token, user] => {
            let (identifier, options) = register_start(state, context, require_webauthn(webauthn)?, now, token, user)?;
            json_text(&identifier, &options)
        }
        ["wa-register-finish", token, user, challenge, name, json @ ..] => {
            let request = RegistrationRequest {
                username: (*user).to_owned(),
                challenge_id: (*challenge).to_owned(),
                name: (*name).to_owned(),
                response: serde_json::from_str(&json.join(" "))?,
            };
            register_finish(state, context, require_webauthn(webauthn)?, now, token, &request).map(|identifier| format!("ok {identifier}"))
        }
        ["wa-login-start", user, password, source] => {
            let request = LoginRequest {
                username: (*user).to_owned(),
                password: SecretString::from(*password),
                totp_code: None,
                source: (*source).to_owned(),
            };
            let (identifier, options) = webauthn_login_start(state, context, require_webauthn(webauthn)?, now, &request)?;
            json_text(&identifier, &options)
        }
        ["passkey-start", source] => {
            let (identifier, options) = passkey_login_start(state, context, require_webauthn(webauthn)?, now, source)?;
            json_text(&identifier, &options)
        }
        ["wa-login-finish", challenge, source, json @ ..] => {
            let assertion = Assertion {
                challenge_id: (*challenge).to_owned(),
                response: serde_json::from_str(&json.join(" "))?,
                source: (*source).to_owned(),
            };
            webauthn_login_finish(state, context, require_webauthn(webauthn)?, now, &assertion).map(|token| format!("ok {}", token.expose_secret()))
        }
        ["wa-list", token, user] => {
            let listed = list_credentials(state, context.catalog, now, token, user)?;
            Ok(listed.iter().map(show_credential).collect::<Vec<_>>().join("\n"))
        }
        ["wa-rename", token, user, identifier, name] => {
            rename_credential(state, context, now, token, (user, identifier, name)).map(|()| "ok".to_owned())
        }
        ["wa-remove", token, user, identifier] => remove_credential(state, context, now, token, (user, identifier)).map(|()| "ok".to_owned()),
        _ => Err(AuthError::Usage("unknown command".to_owned())),
    }
}


pub fn execute_with<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: Option<&Webauthn>,
    now: OffsetDateTime,
    words: &[&str],
) -> Result<String, AuthError> {
    match words {
        ["bootstrap", user, password] => bootstrap_administrator(state, context, now, user, &SecretString::from(*password)).map(show_enrolment),
        ["create", token, user, password, roles] => {
            create_account(state, context, now, token, user, &SecretString::from(*password), parse_roles(roles)).map(|()| "ok".to_owned())
        }
        ["enrol", token, user, rest @ ..] => {
            let code = rest.first().map(|word| SecretString::from(*word));
            enrol_totp(state, context, now, token, user, code.as_ref()).map(show_enrolment)
        }
        ["login", user, password, source, rest @ ..] => {
            let request = LoginRequest {
                username: (*user).to_owned(),
                password: SecretString::from(*password),
                totp_code: rest.first().map(|code| SecretString::from(*code)),
                source: (*source).to_owned(),
            };
            login(state, context, now, &request).map(|token| format!("ok {}", token.expose_secret()))
        }
        ["totp", secret] => totp_now(secret, now),
        ["roles", token, user, roles] => change_roles(state, context, now, token, user, parse_roles(roles)).map(|()| "ok".to_owned()),
        ["revoke", token, target] => revoke_token(state, context, now, token, target).map(|()| "ok".to_owned()),
        ["revoke-all", token, user] => revoke_all_sessions(state, context, now, token, user).map(|count| format!("revoked {count}")),
        ["check", token] => authorize(state, context.catalog, token, now, PERMISSION_EVENTS_READ).map(|user| format!("allowed {user}")),
        _ => execute_webauthn(state, context, webauthn, now, words),
    }
}


pub fn is_read_only(words: &[&str]) -> bool {
    words.first().is_some_and(|command| READ_ONLY_COMMANDS.contains(command))
}


pub fn apply_command<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    store_path: &Path,
    words: &[&str],
) -> Result<String, AuthError> {
    apply_command_with(state, context, None, now, (store_path, words))
}


pub fn undo_login<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    (user_hint, source): (Option<&str>, &str),
    done: &str,
) -> Result<String, AuthError> {
    let revoked = done.strip_prefix("ok ").and_then(|token| revoke_session(&mut state.sessions, token));
    let audit_user = audit_name(&state.accounts, user_hint.or(revoked.as_deref()).unwrap_or(ANONYMOUS_ACTOR));
    let parameters = [("reason", denial_reason(Denial::Internal).to_owned()), ("source", source.to_owned())];
    record(context, now, &audit_user, ACTION_LOGIN, &audit_user, Outcome::Failure, &parameters)?;
    let revocation = [
        ("reason", denial_reason(Denial::Internal).to_owned()),
        ("count", usize::from(revoked.is_some()).to_string()),
    ];
    record(
        context,
        now,
        &audit_user,
        ACTION_SESSION_REVOKE,
        &audit_user,
        Outcome::Success,
        &revocation,
    )?;
    Err(AuthError::InvalidCredentials)
}


/// Runs one command and saves the store only when a mutating command succeeded; a login whose save fails yields no session.
pub fn apply_command_with<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    webauthn: Option<&Webauthn>,
    now: OffsetDateTime,
    (store_path, words): (&Path, &[&str]),
) -> Result<String, AuthError> {
    let updated = if is_read_only(words) {
        let (accounts, credentials) = read_store_locked(store_path)?;
        state.accounts = accounts;
        state.credentials = credentials;
        Updated {
            value: execute_with(state, context, webauthn, now, words)?,
            saved: Ok(()),
        }
    } else {
        update_store_file(store_path, context.random, |accounts, credentials| {
            state.accounts = std::mem::take(accounts);
            state.credentials = std::mem::take(credentials);
            let value = execute_with(state, context, webauthn, now, words)?;
            accounts.clone_from(&state.accounts);
            credentials.clone_from(&state.credentials);
            Ok(value)
        })?
    };
    let Updated { value: done, saved } = updated;
    match (saved, words) {
        (Ok(()), _) => Ok(done),
        (Err(error), ["login", user, _, source, ..]) => {
            tracing::warn!(%error, "store save failed after a successful login");
            undo_login(state, context, now, (Some(user), source), &done)
        }
        (Err(error), ["wa-login-finish", _, source, ..]) => {
            tracing::warn!(%error, "store save failed after a successful WebAuthn login");
            undo_login(state, context, now, (None, source), &done)
        }
        (Err(error), _) => Err(error),
    }
}


pub fn run<Input: BufRead, Output: Write>(
    arguments: &[String],
    input: Input,
    output: Output,
    clock: Clock,
    random: RandomFn,
) -> Result<(), AuthError> {
    match arguments {
        [store, audit, key_file, compromised_file] => {
            serve(&[store, audit, key_file, compromised_file], (None, None), (input, output), clock, random)
        }
        [store, audit, key_file, compromised_file, webauthn_file] => serve(
            &[store, audit, key_file, compromised_file],
            (Some(webauthn_file), None),
            (input, output),
            clock,
            random,
        ),
        [store, audit, key_file, compromised_file, webauthn_file, roles_file] => serve(
            &[store, audit, key_file, compromised_file],
            (Some(webauthn_file), Some(roles_file)),
            (input, output),
            clock,
            random,
        ),
        _ => Err(AuthError::Usage(USAGE.to_owned())),
    }
}


pub fn load_roles(file: &str) -> Result<RoleCatalog, AuthError> {
    load_catalog(File::open(file)?)
}


pub fn load_webauthn(file: &str) -> Result<Webauthn, AuthError> {
    let config = parse_webauthn_config(&std::fs::read_to_string(file)?, file)?;
    build_webauthn(&config)
}


pub fn serve<Input: BufRead, Output: Write>(
    paths: &[&String; PATH_COUNT],
    (webauthn_file, roles_file): (Option<&String>, Option<&String>),
    (input, mut output): (Input, Output),
    clock: Clock,
    random: RandomFn,
) -> Result<(), AuthError> {
    let [store, audit, key_file, compromised_file] = paths;
    let store_path = PathBuf::from(store);
    read_store_locked(&store_path)?;
    let key = read_key_file(key_file)?;
    let audit_log = open_file_log(&PathBuf::from(audit))?;
    let compromised = load_compromised(BufReader::new(File::open(compromised_file)?))?;
    let catalog = roles_file.map(|file| load_roles(file)).transpose()?.unwrap_or_else(builtin_catalog);
    let context = Context {
        audit: &audit_log,
        random,
        verify: &verify_password,
        key: &key,
        compromised: &compromised,
        catalog: &catalog,
        tenant: CLI_TENANT,
        request_id: CLI_REQUEST_ID,
    };
    let webauthn = webauthn_file.map(|file| load_webauthn(file)).transpose()?;
    let mut state = State::default();
    input.lines().try_for_each(|line| {
        let text = line?;
        let words: Vec<&str> = text.split_whitespace().collect();
        let reply = match apply_command_with(&mut state, &context, webauthn.as_ref(), clock(), (&store_path, &words)) {
            Ok(done) => done,
            Err(error) => format!("error {error}"),
        };
        writeln!(output, "{reply}")?;
        Ok::<(), AuthError>(())
    })
}
