use crate::breakers::Breakers;
use crate::check::check;
use crate::config::limits_for;
use crate::error::CommandError;
use crate::grant::{grant_override, OverrideGrant};
use crate::model::{ActionKind, LimitName, ProposedAction, Target};
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::io::{self, BufRead, Write};
use std::time::Duration;


pub const QUIT_COMMAND: &str = "quit";


pub const REQUEST_ID: &str = "cli";


pub const USAGE: &str =
    "isolate <tenant> <target> <fleet> <isolated> [tags] | disable <tenant> <account> [tags] | block-ip <tenant> <ip> <seconds> [tags] | \
                         block-domain <tenant> <domain> <seconds> [tags] | rmm <tenant> <target> <machines> [tags] | \
                         override <tenant> <limit> <seconds> <admin> | limits <tenant> | reload | quit";


pub fn proposed(tenant: &str, id: &str, tags: &[&str], kind: ActionKind) -> ProposedAction {
    ProposedAction {
        tenant: tenant.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        kind,
        target: Target {
            id: id.to_owned(),
            tags: tags
                .iter()
                .flat_map(|list| list.split(','))
                .filter(|tag| !tag.is_empty())
                .map(str::to_owned)
                .collect(),
        },
    }
}


/// Tags are one optional comma separated word at the end of the line.
pub fn parse_action(tokens: &[&str]) -> Result<ProposedAction, CommandError> {
    match tokens {
        ["isolate", tenant, target, fleet, isolated, tags @ ..] => Ok(proposed(
            tenant,
            target,
            tags,
            ActionKind::IsolateEndpoint {
                fleet_size: fleet.parse()?,
                isolated_now: isolated.parse()?,
            },
        )),
        ["disable", tenant, target, tags @ ..] => Ok(proposed(tenant, target, tags, ActionKind::DisableAccount)),
        ["block-ip", tenant, target, seconds, tags @ ..] => Ok(proposed(
            tenant,
            target,
            tags,
            ActionKind::BlockIp {
                address: target.parse()?,
                duration: Duration::from_secs(seconds.parse()?),
            },
        )),
        ["block-domain", tenant, target, seconds, tags @ ..] => Ok(proposed(
            tenant,
            target,
            tags,
            ActionKind::BlockDomain {
                duration: Duration::from_secs(seconds.parse()?),
            },
        )),
        ["rmm", tenant, target, machines, tags @ ..] => Ok(proposed(tenant, target, tags, ActionKind::RmmScript { machines: machines.parse()? })),
        _ => Err(CommandError::Usage(USAGE)),
    }
}


pub fn describe(outcome: &ReloadOutcome) -> String {
    match outcome {
        ReloadOutcome::Unchanged => "unchanged".to_owned(),
        ReloadOutcome::Applied { keys } => format!("applied {}", keys.join(",")),
        ReloadOutcome::Refused { reason } => format!("refused {reason}"),
    }
}


pub fn run_override(breakers: &Breakers, tenant: &str, limit: &str, seconds: &str, admin: &str) -> Result<String, CommandError> {
    let grant = OverrideGrant {
        admin: admin.to_owned(),
        tenant: tenant.to_owned(),
        limit: limit.parse::<LimitName>().map_err(CommandError::Limit)?,
        until: (breakers.clock)() + Duration::from_secs(seconds.parse()?),
        justification: "command line".to_owned(),
        request_id: REQUEST_ID.to_owned(),
    };
    grant_override(breakers, &grant)?;
    Ok(format!("override of {} until {}", grant.limit, grant.until))
}


pub fn execute(breakers: &Breakers, tokens: &[&str]) -> Result<String, CommandError> {
    match tokens {
        ["reload"] => Ok(describe(&reload(&breakers.engine))),
        ["limits", tenant] => {
            let limits = limits_for(&current_config(&breakers.engine), tenant);
            Ok(format!(
                "isolations_per_hour={} isolations_per_day={} disablings_per_hour={} blocks_per_hour={}",
                limits.isolations_per_hour, limits.isolations_per_day, limits.disablings_per_hour, limits.blocks_per_hour
            ))
        }
        ["override", tenant, limit, seconds, admin] => run_override(breakers, tenant, limit, seconds, admin),
        _ => parse_action(tokens).map(|action| check(breakers, &action).to_string()),
    }
}


/// One command per line; a failing command is reported on `out` and the session goes on.
pub fn run_command<Output: Write>(breakers: &Breakers, line: &str, out: &mut Output) -> io::Result<()> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match execute(breakers, &tokens) {
        Ok(text) => writeln!(out, "{text}"),
        Err(error) => writeln!(out, "error: {error}"),
    }
}


/// Reads commands until `quit` or end of input.
pub fn run_session<Input: BufRead, Output: Write>(breakers: &Breakers, input: Input, out: &mut Output) -> io::Result<()> {
    input
        .lines()
        .take_while(|line| line.as_ref().map_or(true, |text| text.trim() != QUIT_COMMAND))
        .try_for_each(|line| line.and_then(|command| run_command(breakers, &command, out)))
}
