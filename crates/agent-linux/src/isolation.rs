use crate::cursor::open_state_dir;
use crate::error::IsolationError;
use crate::model::{IsolationSettings, IsolationStatus, ItemJson, LinuxFile, ListingJson, Protocol, Rule, StateDir};
use crate::settings::invalid_isolation_settings;
use crate::types::NftFn;
use agent_channel::agent_app::load_agent_file;
use agent_channel::app::shared_log_audit;
use agent_channel::spool_dirs::open_parent;
use core_audit::log::open_file_log;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::load::load_file;
use core_config::types::SharedAuditFn;
use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;


pub const TABLE_FAMILY: &str = "inet";


pub const TABLE_NAME: &str = "ostyr_isolation";


pub const CHAIN_INPUT: &str = "input";


pub const CHAIN_OUTPUT: &str = "output";


pub const CHAIN_FORWARD: &str = "forward";


pub const CHAIN_POSTROUTING: &str = "postrouting";


/// RFC 4861: a forwarded neighbour discovery packet cannot still have this hop limit.
pub const ND_HOP_LIMIT: u8 = 255;


/// After connection tracking (-200), so `ct state` is known, and at the mangle slot, well before the usual filter priority 0.
pub const CHAIN_PRIORITY: i64 = -150;


/// After source NAT (100): the postrouting chain judges the destination as DNAT left it.
pub const POSTROUTING_PRIORITY: i64 = 150;


pub const DNS_PORT: u16 = 53;


pub const MAX_LISTING_ITEMS: usize = 64;


pub const CHAIN_COUNT: usize = 4;


pub const ABSENT_MARKER: &str = "No such file or directory";


pub const AUDIT_MODULE: &str = "agent_linux_isolation";


pub const AUDIT_ISOLATE: &str = "isolation.isolate";


pub const AUDIT_RELEASE: &str = "isolation.release";


pub const AUDIT_MISMATCH: &str = "isolation.mismatch";


pub const RESULT_OK: &str = "ok";


pub const RESULT_ABSENT: &str = "absent";


pub const RESULT_MISMATCH: &str = "mismatch";


pub const RESULT_FAILED: &str = "failed";


/// What the isolation commands need: the injected `nft` runner and path, the held state directory, the tenant and the audit log.
pub struct IsolationEnv<'a> {
    pub run: NftFn,
    pub nft: &'a Path,
    pub state: &'a StateDir,
    pub tenant: &'a str,
    pub audit: &'a SharedAuditFn,
}


/// A ruleset file created in the held state directory and removed when dropped; `path` names the open inode (`/proc/<pid>/fd/<n>`), not the directory entry, so a swapped name changes nothing.
#[derive(Debug)]
pub struct RulesetFile {
    pub dir: File,
    pub name: String,
    pub file: File,
    pub path: String,
}


impl Drop for RulesetFile {
    fn drop(&mut self) {
        unlinkat(&self.dir, self.name.as_str(), AtFlags::empty())
            .inspect_err(|error| tracing::warn!(%error, "isolation ruleset file not removed"))
            .ok();
    }
}


pub const ND_TYPES: [&str; 4] = ["nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"];


pub fn family_keyword(address: &IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}


pub fn protocol_keyword(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}


pub fn rule_text(rule: &Rule) -> String {
    match rule {
        Rule::Loopback(keyword) => format!("{keyword} \"lo\" accept"),
        Rule::Neighbour => format!("icmpv6 type {{ {} }} ip6 hoplimit {ND_HOP_LIMIT} accept", ND_TYPES.join(", ")),
        Rule::PathError { address, protocol, port } => format!(
            "{} ct state related ct protocol {} ct original {family} daddr {address} ct original proto-dst {port} accept",
            error_match(address),
            protocol_keyword(*protocol),
            family = family_keyword(address)
        ),
        Rule::Destination { address, protocol, port } => format!(
            "{} daddr {address} {} dport {port} accept",
            family_keyword(address),
            protocol_keyword(*protocol)
        ),
        Rule::Reply { address, protocol, port } => format!(
            "{} saddr {address} {} sport {port} ct state established,related accept",
            family_keyword(address),
            protocol_keyword(*protocol)
        ),
    }
}


/// The only ICMP error each family allows: frag-needed (IPv4) and packet-too-big (IPv6).
pub fn error_match(address: &IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "icmp type destination-unreachable icmp code frag-needed",
        IpAddr::V6(_) => "icmpv6 type packet-too-big",
    }
}


pub fn error_exprs(address: &IpAddr) -> Vec<Value> {
    match address {
        IpAddr::V4(_) => vec![
            matching(
                json!({"payload": {"protocol": "icmp", "field": "type"}}),
                "==",
                json!("destination-unreachable"),
            ),
            matching(json!({"payload": {"protocol": "icmp", "field": "code"}}), "==", json!("frag-needed")),
        ],
        IpAddr::V6(_) => vec![matching(
            json!({"payload": {"protocol": "icmpv6", "field": "type"}}),
            "==",
            json!("packet-too-big"),
        )],
    }
}


fn matching(left: Value, operator: &str, right: Value) -> Value {
    json!({"match": {"op": operator, "left": left, "right": right}})
}


/// The `expr` list `nft -j` prints for the rule, so a listing can be compared with what was rendered.
pub fn rule_exprs(rule: &Rule) -> Vec<Value> {
    let accept = json!({"accept": null});
    match rule {
        Rule::Loopback(keyword) => vec![matching(json!({"meta": {"key": keyword}}), "==", json!("lo")), accept],
        Rule::Neighbour => vec![
            matching(
                json!({"payload": {"protocol": "icmpv6", "field": "type"}}),
                "==",
                json!({"set": ND_TYPES}),
            ),
            matching(json!({"payload": {"protocol": "ip6", "field": "hoplimit"}}), "==", json!(ND_HOP_LIMIT)),
            accept,
        ],
        Rule::PathError { address, protocol, port } => error_exprs(address)
            .into_iter()
            .chain([
                matching(json!({"ct": {"key": "state"}}), "in", json!("related")),
                matching(json!({"ct": {"key": "protocol"}}), "==", json!(protocol_keyword(*protocol))),
                matching(
                    json!({"ct": {"key": format!("{} daddr", family_keyword(address)), "dir": "original"}}),
                    "==",
                    json!(address.to_string()),
                ),
                matching(json!({"ct": {"key": "proto-dst", "dir": "original"}}), "==", json!(port)),
                accept,
            ])
            .collect(),
        Rule::Destination { address, protocol, port } => vec![
            matching(
                json!({"payload": {"protocol": family_keyword(address), "field": "daddr"}}),
                "==",
                json!(address.to_string()),
            ),
            matching(
                json!({"payload": {"protocol": protocol_keyword(*protocol), "field": "dport"}}),
                "==",
                json!(port),
            ),
            accept,
        ],
        Rule::Reply { address, protocol, port } => vec![
            matching(
                json!({"payload": {"protocol": family_keyword(address), "field": "saddr"}}),
                "==",
                json!(address.to_string()),
            ),
            matching(
                json!({"payload": {"protocol": protocol_keyword(*protocol), "field": "sport"}}),
                "==",
                json!(port),
            ),
            matching(json!({"ct": {"key": "state"}}), "in", json!(["established", "related"])),
            accept,
        ],
    }
}


/// Every address, protocol and port the host may talk to: the endpoints over TCP, then each resolver over UDP and TCP.
pub fn allowed_flows(settings: &IsolationSettings) -> Vec<(IpAddr, Protocol, u16)> {
    settings
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.address, Protocol::Tcp, endpoint.port))
        .chain(
            settings
                .dns
                .iter()
                .flat_map(|address| [Protocol::Udp, Protocol::Tcp].map(|protocol| (*address, protocol, DNS_PORT))),
        )
        .collect()
}


/// Loopback of the hook, then what keeps IPv6 neighbours working: neighbour discovery only, never a data channel.
pub fn base_rules(keyword: &'static str) -> Vec<Rule> {
    vec![Rule::Loopback(keyword), Rule::Neighbour]
}


/// One path-MTU error rule per allowed TCP flow, from any source (a router sends it): a UDP flow gets none, an error on it would be a data channel to `IP_RECVERR`.
pub fn error_rules(settings: &IsolationSettings) -> Vec<Rule> {
    allowed_flows(settings)
        .into_iter()
        .filter(|(_, protocol, _)| *protocol == Protocol::Tcp)
        .map(|(address, protocol, port)| Rule::PathError { address, protocol, port })
        .collect()
}


/// Established and related traffic is accepted only as the reply of an allowed flow, so a connection open before isolation dies.
pub fn input_rules(settings: &IsolationSettings) -> Vec<Rule> {
    base_rules("iifname")
        .into_iter()
        .chain(error_rules(settings))
        .chain(
            allowed_flows(settings)
                .into_iter()
                .map(|(address, protocol, port)| Rule::Reply { address, protocol, port }),
        )
        .collect()
}


pub fn output_rules(settings: &IsolationSettings) -> Vec<Rule> {
    base_rules("oifname")
        .into_iter()
        .chain(
            allowed_flows(settings)
                .into_iter()
                .map(|(address, protocol, port)| Rule::Destination { address, protocol, port }),
        )
        .collect()
}


/// Same rules as the output chain, judged after NAT: a DNAT that rewrote an allowed destination to another one is dropped here.
pub fn postrouting_rules(settings: &IsolationSettings) -> Vec<Rule> {
    output_rules(settings)
}


pub fn chain_text(name: &str, priority: i64, rules: &[Rule]) -> String {
    let body: String = rules.iter().map(|rule| format!("        {}\n", rule_text(rule))).collect();
    format!("    chain {name} {{\n        type filter hook {name} priority {priority}; policy drop;\n{body}    }}\n")
}


/// The `nft -f` text: the table is declared, deleted and declared again in one transaction, so a second isolate leaves exactly one table.
pub fn render_ruleset(settings: &IsolationSettings) -> Result<String, IsolationError> {
    if settings.endpoints.is_empty() {
        Err(IsolationError::NoEndpoints)
    } else {
        let table = format!("table {TABLE_FAMILY} {TABLE_NAME}");
        Ok(format!(
            "{table}\ndelete {table}\n{table} {{\n{}{}{}{}}}\n",
            chain_text(CHAIN_INPUT, CHAIN_PRIORITY, &input_rules(settings)),
            chain_text(CHAIN_OUTPUT, CHAIN_PRIORITY, &output_rules(settings)),
            chain_text(CHAIN_FORWARD, CHAIN_PRIORITY, &[]),
            chain_text(CHAIN_POSTROUTING, POSTROUTING_PRIORITY, &postrouting_rules(settings))
        ))
    }
}


/// Creates a fresh file (`O_EXCL`, `O_NOFOLLOW`) relative to the held state directory.
pub fn write_ruleset(state: &StateDir, ruleset: &str) -> Result<RulesetFile, IsolationError> {
    let name = format!(
        "isolation-{}-{}.nft",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let dir = state.handle.try_clone()?;
    let fd = openat(
        &state.handle,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(fd);
    let path = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    let created = RulesetFile { dir, name, file, path };
    (&created.file).write_all(ruleset.as_bytes())?;
    created.file.sync_all()?;
    Ok(created)
}


/// Writes the ruleset to a fresh file and runs `nft -f` on it; the file is removed on every path.
pub async fn apply(run: NftFn, nft: &Path, state: &StateDir, ruleset: &str) -> Result<(), IsolationError> {
    let file = write_ruleset(state, ruleset)?;
    run(nft.to_path_buf(), vec!["-f".to_owned(), file.path.clone()]).await?;
    Ok(())
}


pub fn list_arguments() -> Vec<String> {
    ["-j", "list", "table", TABLE_FAMILY, TABLE_NAME].map(str::to_owned).to_vec()
}


pub fn delete_arguments() -> Vec<String> {
    ["delete", "table", TABLE_FAMILY, TABLE_NAME].map(str::to_owned).to_vec()
}


/// The rules of one chain of the listing, in order.
pub fn chain_exprs(items: &[ItemJson], chain: &str) -> Vec<Vec<Value>> {
    items
        .iter()
        .filter_map(|item| item.rule.as_ref())
        .filter(|rule| rule.family == TABLE_FAMILY && rule.table == TABLE_NAME && rule.chain == chain)
        .map(|rule| rule.expr.clone())
        .collect()
}


/// A chain is as rendered: a filter chain on its own hook at the priority, policy drop.
pub fn chain_is_exact(items: &[ItemJson], name: &str, priority: i64) -> bool {
    let chains: Vec<_> = items
        .iter()
        .filter_map(|item| item.chain.as_ref())
        .filter(|chain| chain.name == name)
        .collect();
    chains.len() == 1
        && chains.iter().all(|chain| {
            chain.family == TABLE_FAMILY
                && chain.table == TABLE_NAME
                && chain.kind.as_deref() == Some("filter")
                && chain.hook.as_deref() == Some(name)
                && chain.prio == Some(priority)
                && chain.policy.as_deref() == Some("drop")
        })
}


/// Checks a `nft -j list table` output against what `render_ruleset` produced: one table, four chains with policy drop, exactly the expected rules.
pub fn check_listing(text: &str, settings: &IsolationSettings) -> Result<(), IsolationError> {
    let listing: ListingJson = serde_json::from_str(text)?;
    if listing.nftables.len() > MAX_LISTING_ITEMS {
        Err(IsolationError::Mismatch("too many items".to_owned()))
    } else {
        let items = listing
            .nftables
            .iter()
            .map(|raw| serde_json::from_str::<ItemJson>(raw.get()))
            .collect::<Result<Vec<_>, _>>()?;
        let expected_input: Vec<Vec<Value>> = input_rules(settings).iter().map(rule_exprs).collect();
        let expected_output: Vec<Vec<Value>> = output_rules(settings).iter().map(rule_exprs).collect();
        let expected_postrouting: Vec<Vec<Value>> = postrouting_rules(settings).iter().map(rule_exprs).collect();
        let tables: Vec<_> = items.iter().filter_map(|item| item.table.as_ref()).collect();
        let rule_count = items.iter().filter(|item| item.rule.is_some()).count();
        let faults: Vec<&str> = [
            (
                "unknown element",
                items
                    .iter()
                    .any(|item| item.table.is_none() && item.chain.is_none() && item.rule.is_none() && item.metainfo.is_none()),
            ),
            (
                "table",
                tables.len() != 1 || tables.iter().any(|table| table.family != TABLE_FAMILY || table.name != TABLE_NAME),
            ),
            (
                "chains",
                items.iter().filter(|item| item.chain.is_some()).count() != CHAIN_COUNT
                    || !chain_is_exact(&items, CHAIN_INPUT, CHAIN_PRIORITY)
                    || !chain_is_exact(&items, CHAIN_OUTPUT, CHAIN_PRIORITY)
                    || !chain_is_exact(&items, CHAIN_FORWARD, CHAIN_PRIORITY)
                    || !chain_is_exact(&items, CHAIN_POSTROUTING, POSTROUTING_PRIORITY),
            ),
            (
                "rules",
                rule_count != expected_input.len() + expected_output.len() + expected_postrouting.len()
                    || chain_exprs(&items, CHAIN_INPUT) != expected_input
                    || chain_exprs(&items, CHAIN_OUTPUT) != expected_output
                    || chain_exprs(&items, CHAIN_POSTROUTING) != expected_postrouting,
            ),
        ]
        .into_iter()
        .filter_map(|(name, faulty)| faulty.then_some(name))
        .collect();
        if faults.is_empty() {
            Ok(())
        } else {
            Err(IsolationError::Mismatch(faults.join(", ")))
        }
    }
}


/// Lists the table and checks it; a table left that does not match is reported, never assumed.
pub async fn read_back(run: NftFn, nft: &Path, settings: &IsolationSettings) -> Result<(), IsolationError> {
    let text = run(nft.to_path_buf(), list_arguments()).await?;
    check_listing(&text, settings)
}


pub fn is_absent(error: &IsolationError) -> bool {
    matches!(error, IsolationError::Exit { stderr, .. } if stderr.contains(ABSENT_MARKER))
}


/// `Absent` when `nft` says there is no such table, `Active` when the table is exactly the rendered one, an error otherwise.
pub async fn status(run: NftFn, nft: &Path, settings: &IsolationSettings) -> Result<IsolationStatus, IsolationError> {
    match read_back(run, nft, settings).await {
        Ok(()) => Ok(IsolationStatus::Active),
        Err(error) if is_absent(&error) => Ok(IsolationStatus::Absent),
        Err(error) => Err(error),
    }
}


/// Deletes the one table and nothing else; the answer says whether it was there.
pub async fn release(run: NftFn, nft: &Path) -> Result<IsolationStatus, IsolationError> {
    match run(nft.to_path_buf(), delete_arguments()).await {
        Ok(_) => Ok(IsolationStatus::Active),
        Err(error) if is_absent(&error) => Ok(IsolationStatus::Absent),
        Err(error) => Err(error),
    }
}


pub fn audit_entry(tenant: &str, action: &str, result: &str) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: AUDIT_MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: AUDIT_MODULE.to_owned(),
        action: action.to_owned(),
        target: format!("{TABLE_FAMILY} {TABLE_NAME}"),
        outcome: if result == RESULT_OK || result == RESULT_ABSENT {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        request_id: action.replace('.', "-"),
        justification: None,
        parameters: [("result", result)]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    }
}


/// One audit record per action; a mismatch is its own action. A failed append is logged and never undoes the action.
pub fn record<Done>(env: &IsolationEnv<'_>, action: &str, outcome: &Result<Done, IsolationError>) {
    let (name, result) = match outcome {
        Ok(_) => (action, RESULT_OK),
        Err(IsolationError::Mismatch(_)) => (AUDIT_MISMATCH, RESULT_MISMATCH),
        Err(_) => (action, RESULT_FAILED),
    };
    record_result(env, name, result);
}


pub fn record_result(env: &IsolationEnv<'_>, name: &str, result: &str) {
    (env.audit)(audit_entry(env.tenant, name, result))
        .inspect_err(|error| tracing::error!(%error, "isolation audit failed"))
        .ok();
}


/// Applies the table, reads it back and audits the result.
pub async fn isolate(env: &IsolationEnv<'_>, settings: &IsolationSettings) -> Result<(), IsolationError> {
    let outcome = match render_ruleset(settings) {
        Ok(ruleset) => match apply(env.run, env.nft, env.state, &ruleset).await {
            Ok(()) => read_back(env.run, env.nft, settings).await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    record(env, AUDIT_ISOLATE, &outcome);
    outcome
}


/// Deletes the table and audits it.
pub async fn release_audited(env: &IsolationEnv<'_>) -> Result<IsolationStatus, IsolationError> {
    let outcome = release(env.run, env.nft).await;
    match outcome {
        Ok(IsolationStatus::Absent) => record_result(env, AUDIT_RELEASE, RESULT_ABSENT),
        _ => record(env, AUDIT_RELEASE, &outcome),
    }
    outcome
}


/// One action of the example command: the settings file is read once, the state directory is held, the audit log is the agent's own.
pub async fn run_isolation(path: &Path, action: &str, run: NftFn) -> Result<String, IsolationError> {
    let file = load_file::<LinuxFile>(path)?;
    let invalid = invalid_isolation_settings(&file);
    if !invalid.is_empty() {
        Err(IsolationError::Settings(invalid.join(", ")))
    } else {
        let agent = load_agent_file(&file.agent_file)?;
        let _audit_dir = open_parent(&file.audit_file)?;
        let state = open_state_dir(&file.cursor_file)?;
        let log = Arc::new(open_file_log(&file.audit_file)?);
        let audit = shared_log_audit(&log);
        let env = IsolationEnv {
            run,
            nft: &file.nft_path,
            state: &state,
            tenant: &agent.tenant,
            audit: &*audit,
        };
        match action {
            "isolate" => isolate(&env, &file.isolation).await.map(|()| "isolated".to_owned()),
            "release" => release_audited(&env).await.map(|before| format!("released, table was {before:?}")),
            "status" => status_audited(&env, &file.isolation).await.map(|now| format!("status: {now:?}")),
            _ => Err(IsolationError::Usage),
        }
    }
}


/// Reads the table back and audits a mismatch (a present, exact table and an absent one are not recorded).
pub async fn status_audited(env: &IsolationEnv<'_>, settings: &IsolationSettings) -> Result<IsolationStatus, IsolationError> {
    let outcome = status(env.run, env.nft, settings).await;
    if matches!(outcome, Err(IsolationError::Mismatch(_))) {
        record(env, AUDIT_ISOLATE, &outcome);
    }
    outcome
}
