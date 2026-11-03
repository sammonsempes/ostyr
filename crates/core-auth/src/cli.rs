use crate::error::AuthError;
use crate::policy::load_compromised;
use crate::rbac::{builtin_catalog, PERMISSION_EVENTS_READ};
use crate::service::{authorize, change_roles, create_account, enrol_totp, login, revoke_all_sessions, Context, LoginRequest, State};
use crate::store::{load_accounts_file, save_accounts_file};
use crate::totp::{code_for_step, unix_seconds, TOTP_STEP_SECONDS};
use crate::types::{Clock, RandomFn, RoleSet};
use core_audit::log::open_file_log;
use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use time::OffsetDateTime;


pub const PATH_COUNT: usize = 4;


pub const CLI_ACTOR: &str = "cli";


pub const CLI_TENANT: &str = "default";


pub const CLI_REQUEST_ID: &str = "cli";


pub const USAGE: &str = "usage: auth_tool <store> <audit-log> <key-file> <compromised-list>; commands on stdin";


pub fn parse_roles(text: &str) -> RoleSet {
    text.split(',').filter(|role| !role.is_empty()).map(str::to_owned).collect()
}


pub fn totp_now(secret_text: &str, now: OffsetDateTime) -> Result<String, AuthError> {
    let secret = BASE32_NOPAD
        .decode(secret_text.as_bytes())
        .map_err(|error| AuthError::Usage(format!("secret is not base32: {error}")))?;
    Ok(code_for_step(&secret, unix_seconds(now)? / TOTP_STEP_SECONDS))
}


pub fn execute<Output: Write>(state: &mut State, context: &Context<Output>, now: OffsetDateTime, words: &[&str]) -> Result<String, AuthError> {
    match words {
        ["create", user, password, roles] => {
            create_account(state, context, now, CLI_ACTOR, user, &SecretString::from(*password), parse_roles(roles)).map(|()| "ok".to_owned())
        }
        ["enrol", user] => enrol_totp(state, context, now, CLI_ACTOR, user).map(|enrolment| {
            let codes: Vec<&str> = enrolment.backup_codes.iter().map(|code| code.expose_secret()).collect();
            format!("secret {}\nbackup {}", enrolment.secret.expose_secret(), codes.join(" "))
        }),
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
        ["roles", user, roles] => change_roles(state, context, now, CLI_ACTOR, user, parse_roles(roles)).map(|()| "ok".to_owned()),
        ["revoke-all", user] => revoke_all_sessions(state, context, now, CLI_ACTOR, user).map(|count| format!("revoked {count}")),
        ["check", token] => authorize(state, context.catalog, token, now, PERMISSION_EVENTS_READ).map(|user| format!("allowed {user}")),
        _ => Err(AuthError::Usage("unknown command".to_owned())),
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
        [store, audit, key_file, compromised_file] => serve(&[store, audit, key_file, compromised_file], input, output, clock, random),
        _ => Err(AuthError::Usage(USAGE.to_owned())),
    }
}


pub fn serve<Input: BufRead, Output: Write>(
    paths: &[&String; PATH_COUNT],
    input: Input,
    mut output: Output,
    clock: Clock,
    random: RandomFn,
) -> Result<(), AuthError> {
    let [store, audit, key_file, compromised_file] = paths;
    let store_path = PathBuf::from(store);
    let audit_log = open_file_log(&PathBuf::from(audit))?;
    let key = SecretSlice::from(fs::read(key_file)?);
    let compromised = load_compromised(BufReader::new(File::open(compromised_file)?))?;
    let catalog = builtin_catalog();
    let context = Context {
        audit: &audit_log,
        random,
        key: &key,
        compromised: &compromised,
        catalog: &catalog,
        tenant: CLI_TENANT,
        request_id: CLI_REQUEST_ID,
    };
    let mut state = State {
        accounts: load_accounts_file(&store_path)?,
        ..State::default()
    };
    input.lines().try_for_each(|line| {
        let text = line?;
        let words: Vec<&str> = text.split_whitespace().collect();
        let reply = match execute(&mut state, &context, clock(), &words) {
            Ok(done) => done,
            Err(error) => format!("error {error}"),
        };
        save_accounts_file(&store_path, &state.accounts)?;
        writeln!(output, "{reply}")?;
        Ok::<(), AuthError>(())
    })
}
