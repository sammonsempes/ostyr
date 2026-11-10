use crate::error::CliError;
use crate::model::{Action, Command, KeyClass, PackageSelection, RebootPolicy, Verifier};
use crate::sign::{memory_signer, new_nonce, sign_command};
use crate::types::FillFn;
use crate::verify::{action_name, verify_command};
use data_encoding::HEXLOWER;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTimeError};
use tracing::{warn, Dispatch};
use tracing_subscriber::fmt::writer::BoxMakeWriter;


pub const SIGN_USAGE: &str = "sign <seed-hex> <key-id> <class> <agent> <tenant> <sequence> <action> [parameter]";


/// Plain-text events to the given writer (stderr in the example), so refusals and clock warnings are visible.
pub fn log_dispatch(writer: BoxMakeWriter) -> Dispatch {
    Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(writer).finish())
}


pub const COMMAND_LIFETIME_SECONDS: u64 = 60;


/// A clock before the epoch is logged and read as 0, which refuses every command (issued in the future).
pub fn seconds_since_epoch(elapsed: Result<Duration, SystemTimeError>) -> u64 {
    elapsed.map_or_else(
        |error| {
            warn!(error = %error, "system clock is before the Unix epoch, treating it as 0");
            0
        },
        |duration| duration.as_secs(),
    )
}


/// Writes `seed <hex>` and `public <hex>` for a fresh random key.
pub fn write_keypair<Output: Write>(fill: FillFn, out: &mut Output) -> Result<(), CliError> {
    let mut seed = [0; SECRET_KEY_LENGTH];
    fill(&mut seed)?;
    let public = SigningKey::from_bytes(&seed).verifying_key();
    writeln!(out, "seed {}", HEXLOWER.encode(&seed))?;
    writeln!(out, "public {}", HEXLOWER.encode(&public.to_bytes()))?;
    Ok(())
}


pub fn parse_action(name: &str, parameter: Option<&str>) -> Result<Action, CliError> {
    let text = parameter.map_or_else(String::new, str::to_owned);
    match name {
        "ping" => Ok(Action::Ping),
        "collect_status" => Ok(Action::CollectStatus),
        "isolate" => Ok(Action::Isolate),
        "uninstall" => Ok(Action::Uninstall),
        "run_script" => Ok(Action::RunScript { script: text }),
        "update" => Ok(Action::Update { version: text }),
        "change_policy" => Ok(Action::ChangePolicy { policy: text }),
        "install_updates" => parse_install_updates(&text),
        "reboot" => parse_reboot(&text),
        "kill" => text.parse().map(|process_id| Action::Kill { process_id }).map_err(|_| CliError::Number),
        other => Err(CliError::UnknownAction(other.to_owned())),
    }
}


/// `<never|in_window|required>` or `<policy>=<package>,<package>`; no package list means every allowed update.
pub fn parse_install_updates(text: &str) -> Result<Action, CliError> {
    let (policy, list) = text.split_once('=').map_or((text, None), |(policy, list)| (policy, Some(list)));
    let reboot = match policy {
        "never" => Ok(RebootPolicy::Never),
        "in_window" => Ok(RebootPolicy::InWindow),
        "required" => Ok(RebootPolicy::Required),
        _ => Err(CliError::Parameter("reboot policy must be never, in_window or required")),
    }?;
    let packages = list.map_or(PackageSelection::AllAllowed, |names| {
        PackageSelection::Named(names.split(',').map(str::to_owned).collect())
    });
    Ok(Action::InstallUpdates { packages, reboot })
}


/// `<true|false>,<deadline-seconds>`.
pub fn parse_reboot(text: &str) -> Result<Action, CliError> {
    let (prompt, deadline) = text.split_once(',').ok_or(CliError::Parameter("reboot takes <true|false>,<deadline>"))?;
    Ok(Action::Reboot {
        prompt_user: prompt.parse().map_err(|_| CliError::Parameter("reboot prompt must be true or false"))?,
        deadline: parse_sequence(deadline)?,
    })
}


pub fn parse_class(text: &str) -> Result<KeyClass, CliError> {
    match text {
        "routine" => Ok(KeyClass::Routine),
        "sensitive" => Ok(KeyClass::Sensitive),
        other => Err(CliError::Class(other.to_owned())),
    }
}


pub fn parse_sequence(text: &str) -> Result<u64, CliError> {
    text.parse().map_err(|_| CliError::Number)
}


pub fn signing_key_from(seed_hex: &str) -> Result<SigningKey, CliError> {
    let seed = <[u8; SECRET_KEY_LENGTH]>::try_from(HEXLOWER.decode(seed_hex.as_bytes())?.as_slice()).map_err(|_| CliError::Seed)?;
    Ok(SigningKey::from_bytes(&seed))
}


/// Writes the signed envelope as one hexadecimal line.
pub fn write_signed<Output: Write>(args: &[&str], now: u64, fill: FillFn, out: &mut Output) -> Result<(), CliError> {
    match args {
        [seed, key_id, class, agent_id, tenant, sequence, action] | [seed, key_id, class, agent_id, tenant, sequence, action, _] => {
            let command = Command {
                key_id: (*key_id).to_owned(),
                key_class: parse_class(class)?,
                agent_id: (*agent_id).to_owned(),
                tenant: (*tenant).to_owned(),
                issued_at: now,
                expires_at: now + COMMAND_LIFETIME_SECONDS,
                sequence: parse_sequence(sequence)?,
                nonce: new_nonce(fill)?,
                action: parse_action(action, args.get(SIGN_PARAMETER_INDEX).copied())?,
            };
            let envelope = sign_command(&command, key_id, &memory_signer(signing_key_from(seed)?))?;
            writeln!(out, "{}", HEXLOWER.encode(&envelope))?;
            Ok(())
        }
        _ => Err(CliError::Usage(SIGN_USAGE)),
    }
}


pub const SIGN_PARAMETER_INDEX: usize = 7;


/// One hexadecimal envelope per line in; `accepted <action>` or `refused <reason>` per line out, flushed so a peer can read it live.
pub fn verify_session<Input: BufRead, Output: Write>(
    verifier: &Verifier,
    input: Input,
    out: &mut Output,
    clock: fn() -> u64,
) -> Result<(), CliError> {
    input.lines().try_for_each(|line| {
        let verdict = match HEXLOWER.decode(line?.trim().as_bytes()) {
            Ok(bytes) => match verify_command(verifier, &bytes, clock()) {
                Ok(command) => format!("accepted {}", action_name(&command.action)),
                Err(refusal) => format!("refused {refusal}"),
            },
            Err(error) => format!("refused not hexadecimal: {error}"),
        };
        writeln!(out, "{verdict}")?;
        Ok(out.flush()?)
    })
}
