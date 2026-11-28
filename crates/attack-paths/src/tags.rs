use crate::error::TagsError;
use crate::input::{is_unchanged, open_stamped, run_mid_read, untouched, Stamp};
use crate::model::{Graph, NodeKind, Tags, MAX_TAGS};
use crate::types::MidRead;
use crate::types::{ApplyResult, TagsResult};
use core_config::parse::{parse_document, read_text};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;


pub const TRAILER_PREFIX: &str = "complete: sha256:";


pub const DIGEST_HEX_BYTES: usize = 64;


pub const TRAILER_BYTES: usize = TRAILER_PREFIX.len() + DIGEST_HEX_BYTES + 1;


pub fn kind_is_critical(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::DomainController | NodeKind::AdCs | NodeKind::BackupServer | NodeKind::Hypervisor | NodeKind::SecretsVault
    )
}


/// Strict manual tag file: an unknown key is refused and the list is bounded.
pub fn load_tags(path: &Path) -> TagsResult {
    load_tags_with(path, untouched)
}


/// Reads through one handle opened without following a symlink; a stamp that differs after the read refuses the file, so a half-written list is never used.
pub fn read_stable(path: &Path, mid_read: MidRead) -> Result<(String, Stamp), TagsError> {
    let name = path.display().to_string();
    let (mut handle, before) = open_stamped(path, &name)?;
    let text = read_text(&mut handle, &name)?;
    run_mid_read(mid_read, path, &name)?;
    is_unchanged(&handle, &before, &name)?.then_some(()).ok_or(TagsError::Changed)?;
    Ok((text, before))
}


/// The parsed tags of a sealed file read through one stable handle.
pub fn load_tags_with(path: &Path, mid_read: MidRead) -> TagsResult {
    let name = path.display().to_string();
    let (text, _stamp) = read_stable(path, mid_read)?;
    let body = verify_sealed(&text)?;
    let tags: Tags = parse_document(body, &name)?;
    check_tags(tags)
}


pub fn digest_hex(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}


/// The body followed by its trailer line: `complete: sha256:` and the lowercase hex SHA-256 of every byte before it.
pub fn sealed_text(body: &str) -> String {
    format!("{body}{TRAILER_PREFIX}{}\n", digest_hex(body))
}


/// The body of a sealed file; a carriage return, a missing or malformed trailer, or a digest that is not the body's is refused with fixed text.
pub fn verify_sealed(text: &str) -> Result<&str, TagsError> {
    if text.contains('\r') {
        Err(TagsError::CarriageReturn)
    } else {
        let (body, digits) = split_trailer(text).ok_or(TagsError::Incomplete)?;
        (digest_hex(body) == digits).then_some(body).ok_or(TagsError::Altered)
    }
}


/// The body and the 64 hex digits of the last 82 bytes, which must be `complete: sha256:`, 64 characters of `[0-9a-f]` and a newline, after a newline or nothing.
pub fn split_trailer(text: &str) -> Option<(&str, &str)> {
    let cut = text.len().checked_sub(TRAILER_BYTES)?;
    let (body, tail) = text.split_at_checked(cut)?;
    let digits = tail.strip_prefix(TRAILER_PREFIX)?.strip_suffix('\n')?;
    (digits.bytes().all(is_lower_hex) && (body.is_empty() || body.ends_with('\n'))).then_some((body, digits))
}


pub fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}


pub fn check_tags(tags: Tags) -> TagsResult {
    if tags.critical.len() > MAX_TAGS {
        Err(TagsError::TooMany {
            count: tags.critical.len(),
            max: MAX_TAGS,
        })
    } else {
        Ok(tags)
    }
}


/// Marks every node of a critical kind, and every node the manual tags name, as critical; a tag naming no node is refused.
pub fn apply_tags(graph: &mut Graph, tags: &Tags) -> ApplyResult {
    let known = known_ids(graph);
    tags.critical.iter().enumerate().try_for_each(|(index, tagged)| {
        if known.contains(tagged.as_str()) {
            Ok(())
        } else {
            Err(TagsError::UnknownNode { index })
        }
    })?;
    mark_critical(graph, tags);
    Ok(())
}


/// A tag naming a node the graph does not hold: its position in the file and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedTag {
    pub index: usize,
    pub id: String,
}


/// Same marking for a graph where a node was removed, so a tagged node may be the one that was cut: an unknown tag is skipped and returned.
pub fn apply_tags_lenient(graph: &mut Graph, tags: &Tags) -> Vec<SkippedTag> {
    let known = known_ids(graph);
    let skipped: Vec<SkippedTag> = tags
        .critical
        .iter()
        .enumerate()
        .filter(|(_, tagged)| !known.contains(tagged.as_str()))
        .map(|(index, tagged)| SkippedTag { index, id: tagged.clone() })
        .collect();
    mark_critical(graph, tags);
    skipped
}


pub fn known_ids(graph: &Graph) -> BTreeSet<String> {
    graph.nodes.iter().map(|node| node.id.clone()).collect()
}


pub fn mark_critical(graph: &mut Graph, tags: &Tags) {
    let manual: BTreeSet<&str> = tags.critical.iter().map(String::as_str).collect();
    let marked: BTreeSet<String> = graph
        .nodes
        .iter()
        .filter(|node| kind_is_critical(node.kind) || manual.contains(node.id.as_str()))
        .map(|node| node.id.clone())
        .collect();
    graph
        .nodes
        .iter_mut()
        .for_each(|node| node.critical = node.critical || marked.contains(&node.id));
}
