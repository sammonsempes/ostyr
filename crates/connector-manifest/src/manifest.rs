use crate::error::ConnectorError;
use crate::model::{
    ConfigField, ConfigKind, Manifest, MANIFEST_NAME, MAX_ALIASES, MAX_DEFAULT_BYTES, MAX_FILE_NAME_BYTES, MAX_MANIFEST_BYTES, MAX_NAME_BYTES,
    MAX_REPLAYED_EVENTS, MAX_REPLAY_DEPTH, MAX_SCOPE_BYTES,
};
use core_config::parse::describe_error;
use serde::de::DeserializeOwned;
use serde_saphyr::{alias_limits, options, Budget};
use std::collections::BTreeSet;


pub fn lower_alnum(character: char) -> bool {
    matches!(character, 'a'..='z' | '0'..='9')
}


pub fn name_rest(character: char) -> bool {
    matches!(character, 'a'..='z' | '0'..='9' | '_' | '-' | '.')
}


pub fn scope_rest(character: char) -> bool {
    matches!(character, 'a'..='z' | '0'..='9' | '_' | '-' | '.' | ':')
}


pub fn file_first(character: char) -> bool {
    matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9')
}


pub fn file_rest(character: char) -> bool {
    matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.')
}


/// An ASCII allowlist: a non-empty text of at most `max` bytes whose first character satisfies `first`, never `-`, and the rest `rest`.
pub fn in_grammar(text: &str, max: usize, first: fn(char) -> bool, rest: fn(char) -> bool) -> bool {
    let mut characters = text.chars();
    let first_ok = characters.next().is_some_and(first);
    first_ok && text.len() <= max && characters.all(rest)
}


pub fn valid_name(text: &str) -> bool {
    in_grammar(text, MAX_NAME_BYTES, lower_alnum, name_rest)
}


pub fn valid_scope(text: &str) -> bool {
    in_grammar(text, MAX_SCOPE_BYTES, lower_alnum, scope_rest)
}


pub fn valid_file_name(text: &str) -> bool {
    in_grammar(text, MAX_FILE_NAME_BYTES, file_first, file_rest)
}


pub fn check(condition: bool, field: &'static str) -> Result<(), ConnectorError> {
    condition.then_some(()).ok_or(ConnectorError::Invalid { field })
}


pub fn all_distinct(names: &[&str]) -> bool {
    names.iter().collect::<BTreeSet<_>>().len() == names.len()
}


/// A secret file never carries a default; any other default is bounded.
pub fn default_allowed(field: &ConfigField) -> bool {
    match (field.kind, &field.default) {
        (ConfigKind::SecretFile, Some(_)) => false,
        (_, Some(default)) => default.len() <= MAX_DEFAULT_BYTES,
        (_, None) => true,
    }
}


/// The grammar and uniqueness rules; the counts were enforced while parsing.
pub fn validate_manifest(manifest: &Manifest) -> Result<(), ConnectorError> {
    let action_names: Vec<&str> = manifest.actions.iter().map(|action| action.name.as_str()).collect();
    let field_names: Vec<&str> = manifest.config.iter().map(|field| field.name.as_str()).collect();
    check(valid_name(&manifest.name), "name")?;
    check(valid_name(&manifest.publisher), "publisher")?;
    check(manifest.rights.iter().all(|right| valid_scope(&right.scope)), "rights.scope")?;
    check(action_names.iter().all(|name| valid_name(name)), "actions.name")?;
    check(all_distinct(&action_names), "actions.name")?;
    check(
        manifest
            .actions
            .iter()
            .all(|action| action.targets.iter().all(|target| valid_scope(target))),
        "actions.targets",
    )?;
    check(field_names.iter().all(|name| valid_name(name)), "config.name")?;
    check(all_distinct(&field_names), "config.name")?;
    check(manifest.config.iter().all(default_allowed), "config.default")
}


/// Anchors and aliases are allowed only up to a small fixed count, and the events they replay are capped.
pub fn strict_options() -> serde_saphyr::Options {
    let mut budget = Budget::default();
    budget.max_aliases = MAX_ALIASES;
    budget.max_anchors = MAX_ALIASES;
    let mut parser_options = options! { with_snippet: false };
    parser_options.budget = Some(budget);
    parser_options.alias_limits = alias_limits! {
        max_total_replayed_events: MAX_REPLAYED_EVENTS,
        max_replay_stack_depth: MAX_REPLAY_DEPTH,
        max_alias_expansions_per_anchor: MAX_ALIASES,
    };
    parser_options
}


/// The error carries the parser's error class, never text taken from the document.
pub fn parse_strict<Document: DeserializeOwned>(text: &str, file: &str) -> Result<Document, ConnectorError> {
    serde_saphyr::from_str_with_options(text, strict_options()).map_err(|error| ConnectorError::Document {
        file: file.to_owned(),
        message: describe_error(&error),
    })
}


/// The size is checked first, then the text is parsed strictly (unknown keys, bounded sequences) and validated; the bytes are the ones the caller hashed.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, ConnectorError> {
    (bytes.len() <= MAX_MANIFEST_BYTES)
        .then_some(())
        .ok_or(ConnectorError::ManifestTooLarge { max: MAX_MANIFEST_BYTES })?;
    let text = std::str::from_utf8(bytes).map_err(|_| ConnectorError::Invalid { field: "encoding" })?;
    let manifest: Manifest = parse_strict(text, MANIFEST_NAME)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}
