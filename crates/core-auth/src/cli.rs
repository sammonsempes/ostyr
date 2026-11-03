use crate::error::AuthError;
use crate::password::verify_password;
use crate::policy::load_compromised;
use crate::rbac::{builtin_catalog, PERMISSION_EVENTS_READ};
use crate::secretbox::KEY_BYTES;
use crate::service::{
    authorize, bootstrap_administrator, change_roles, create_account, enrol_totp, login, revoke_all_sessions, revoke_token, Context, Enrolment,
    LoginRequest, State,
};
use crate::store::{load_accounts_file, save_accounts_file};
use crate::totp::{code_for_step, unix_seconds, TOTP_STEP_SECONDS};
use crate::types::{Clock, RandomFn, RoleSet, StoreKey};
use core_audit::log::{check_private, open_file_log, owner_only};
use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use time::OffsetDateTime;


pub const PATH_COUNT: usize = 4;


pub const KEY_READ_LIMIT: u64 = 33;


pub const LOCK_SUFFIX: &str = ".lock";


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


/// Holds an exclusive advisory lock on `<store>.lock` until the returned file is dropped.
pub fn lock_store(store: &str) -> Result<File, AuthError> {
    let file = owner_only(OpenOptions::new().write(true).create(true).truncate(false)).open(format!("{store}{LOCK_SUFFIX}"))?;
    file.lock()?;
    Ok(file)
}


pub fn execute<Output: Write>(state: &mut State, context: &Context<Output>, now: OffsetDateTime, words: &[&str]) -> Result<String, AuthError> {
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
    let _store_lock = lock_store(store)?;
    let store_path = PathBuf::from(store);
    let key = read_key_file(key_file)?;
    let audit_log = open_file_log(&PathBuf::from(audit))?;
    let compromised = load_compromised(BufReader::new(File::open(compromised_file)?))?;
    let catalog = builtin_catalog();
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
    let mut state = State {
        accounts: load_accounts_file(&store_path)?,
        ..State::default()
    };
    input.lines().try_for_each(|line| {
        let text = line?;
        let words: Vec<&str> = text.split_whitespace().collect();
        let reply = match execute(&mut state, &context, clock(), &words) {
            Ok(done) => {
                save_accounts_file(&store_path, &state.accounts, random)?;
                done
            }
            Err(error) => format!("error {error}"),
        };
        writeln!(output, "{reply}")?;
        Ok::<(), AuthError>(())
    })
}
