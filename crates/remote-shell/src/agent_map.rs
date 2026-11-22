use crate::grammar::valid_reference;
use agent_channel::identity::valid_component;
use agent_channel::model::Identity;
use core_config::error::ConfigError;
use core_config::parse::{open_regular, parse_document, read_text_capped, MAX_FILE_BYTES};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::scope::tenant_scope;
use serde::de::{Deserializer, Error, IgnoredAny, SeqAccess};
use serde::Deserialize;
use serde_untagged::UntaggedEnumVisitor;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};


pub const MAX_AGENT_ASSETS: usize = 30_000;


pub const TOO_MANY_ENTRIES: &str = "too many agent entries";


pub const STATE_PREFIX: &str = "agents.";


/// The operator-declared file: which agent serves which asset, for one tenant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub tenant: String,
    pub agents: Vec<AgentEntry>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEntry {
    pub agent_id: String,
    pub asset: String,
}


/// A validated mapping: asset (byte-exact) to agent id, for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMap {
    pub tenant: String,
    pub agents: BTreeMap<String, String>,
}


/// Reads at most `MAX_AGENT_ASSETS + 1` entries as `IgnoredAny`, so the entry after the cap is never built, and refuses a longer sequence.
pub fn count_entries<'de, Source>(deserializer: Source) -> Result<Vec<IgnoredAny>, Source::Error>
where
    Source: Deserializer<'de>,
{
    UntaggedEnumVisitor::new()
        .expecting("a sequence of agent entries")
        .seq(|mut seq| {
            let items = std::iter::from_fn(|| seq.next_element::<IgnoredAny>().transpose())
                .take(MAX_AGENT_ASSETS.saturating_add(1))
                .collect::<Result<Vec<IgnoredAny>, _>>()?;
            (items.len() <= MAX_AGENT_ASSETS)
                .then_some(items)
                .ok_or_else(|| Error::custom(TOO_MANY_ENTRIES))
        })
        .deserialize(deserializer)
}


/// Pass 1 mirror of `AgentFile`: only the entry count; a failure is a fixed text, never the erased parser message.
#[derive(Debug, Deserialize)]
pub struct CountFile {
    #[serde(default, deserialize_with = "count_entries")]
    pub agents: Vec<IgnoredAny>,
}


/// Pass 1: counts the entries without building them; every error becomes fixed text with the index, never the erased parser message.
pub fn count_agents(text: &str, file: &str) -> Result<(), ConfigError> {
    parse_document::<CountFile>(text, file).map(drop).map_err(|error| match error {
        ConfigError::Parse { message, .. } if message.starts_with(TOO_MANY_ENTRIES) => {
            refuse(file, format!("agents[{MAX_AGENT_ASSETS}]: {TOO_MANY_ENTRIES}"))
        }
        _ => refuse(file, "the document is not a valid agent file".to_owned()),
    })
}


pub fn refuse(file: &str, reason: String) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.to_owned(),
        reason,
    }
}


/// The indexes of the first two keys equal after ASCII case folding.
pub fn first_duplicate<'a>(keys: impl Iterator<Item = &'a str>) -> Option<(usize, usize)> {
    keys.enumerate()
        .try_fold(BTreeMap::new(), |mut seen, (index, key)| {
            match seen.insert(key.to_ascii_lowercase(), index) {
                Some(first) => Err((first, index)),
                None => Ok(seen),
            }
        })
        .err()
}


/// The first grammar failure, as the index and the field name (never the value).
pub fn first_bad_entry(entries: &[AgentEntry]) -> Option<(usize, &'static str)> {
    entries.iter().enumerate().find_map(|(index, entry)| {
        if !valid_component(&entry.agent_id) {
            Some((index, "agent_id"))
        } else if !valid_reference(&entry.asset) {
            Some((index, "asset"))
        } else {
            None
        }
    })
}


/// Checks the tenant, the grammars and the uniqueness of assets and agent ids; every refusal names a field and an index, never a value.
pub fn validate_file(file: &str, parsed: AgentFile, tenant: &str) -> Result<AgentMap, ConfigError> {
    tenant_scope(&parsed.tenant).map_err(|_| refuse(file, "`tenant` is outside its grammar".to_owned()))?;
    if parsed.tenant != tenant {
        Err(refuse(file, "`tenant` is not the tenant of this engine".to_owned()))
    } else if let Some((index, field)) = first_bad_entry(&parsed.agents) {
        Err(refuse(file, format!("agents[{index}].{field} is outside its grammar")))
    } else if let Some((first, second)) = first_duplicate(parsed.agents.iter().map(|entry| entry.asset.as_str())) {
        Err(refuse(file, format!("agents[{second}].asset repeats agents[{first}].asset")))
    } else if let Some((first, second)) = first_duplicate(parsed.agents.iter().map(|entry| entry.agent_id.as_str())) {
        Err(refuse(file, format!("agents[{second}].agent_id repeats agents[{first}].agent_id")))
    } else {
        Ok(AgentMap {
            tenant: parsed.tenant,
            agents: parsed.agents.into_iter().map(|entry| (entry.asset, entry.agent_id)).collect(),
        })
    }
}


/// Reads at most `MAX_FILE_BYTES` from `reader` and parses exactly those bytes.
pub fn parse_agent_map(reader: &mut dyn Read, file: &str, tenant: &str) -> Result<AgentMap, ConfigError> {
    let text = read_text_capped(reader, file, MAX_FILE_BYTES)?;
    count_agents(&text, file)?;
    let parsed = parse_document::<AgentFile>(&text, file)?;
    validate_file(file, parsed, tenant)
}


/// A FIFO or device at the path is refused on the opened handle.
pub fn load_agent_map(path: &Path, tenant: &str) -> Result<AgentMap, ConfigError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path, &file)?;
    parse_agent_map(&mut handle, &file, tenant)
}


pub fn agent_loader(path: PathBuf, tenant: String) -> Box<LoaderFn<AgentMap>> {
    Box::new(move || load_agent_map(&path, &tenant))
}


/// One key per asset: `agents.<asset>` to the agent id.
pub fn agent_state(map: &AgentMap) -> ConfigState {
    map.agents
        .iter()
        .map(|(asset, agent_id)| (format!("{STATE_PREFIX}{asset}"), agent_id.clone()))
        .collect()
}


/// A bad or missing first file is an error: the engine never starts with an empty mapping.
pub fn open_agent_engine(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<AgentMap>, ConfigError> {
    open_engine(agent_loader(path, context.tenant.clone()), agent_state, Vec::new(), audit, context)
}


/// Byte-exact on tenant and asset; the caller uses the returned identity for dispatch and the same asset string for the criticality lookup.
pub fn resolve_agent(snapshot: &AgentMap, tenant: &str, asset: &str) -> Option<Identity> {
    (snapshot.tenant == tenant)
        .then(|| snapshot.agents.get(asset))
        .flatten()
        .map(|agent_id| Identity {
            tenant: tenant.to_owned(),
            agent_id: agent_id.clone(),
        })
}
