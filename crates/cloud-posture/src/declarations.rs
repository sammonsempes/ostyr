use crate::error::DeclarationError;
use crate::model::{Cluster, Declarations};
use crate::text::valid_reference;
use core_pg::scope::{tenant_of, tenant_scope};
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;


pub const MAX_CLUSTERS: usize = 64;


pub const MAX_DECLARATION_BYTES: u64 = 65_536;


pub const MAX_KUBECONFIG_PATH_BYTES: usize = 1_024;


pub const MAX_CLUSTER_REFERENCE_BYTES: usize = 256;


pub const PATH_PUNCTUATION: &str = "_.-/+@";


#[derive(Deserialize)]
struct ClusterCount {
    clusters: Vec<IgnoredAny>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeclarations {
    tenant: String,
    clusters: Vec<serde_json::Value>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCluster {
    name: String,
    kubeconfig_file: String,
    context: String,
}


/// A relative path of ASCII alphanumerics and `_.-/+@` within the byte cap: no empty, `.` or `..` segment and no segment starting with `-`.
pub fn valid_kubeconfig_path(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_KUBECONFIG_PATH_BYTES
        && text.chars().all(|next| next.is_ascii_alphanumeric() || PATH_PUNCTUATION.contains(next))
        && text
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != ".." && !segment.starts_with('-'))
}


/// One entry, refused whole when it is not exactly the three fields or one field breaks its grammar.
pub fn cluster_of(value: serde_json::Value, tenant_directory: &Path) -> Option<Cluster> {
    serde_json::from_value::<RawCluster>(value)
        .ok()
        .filter(|raw| valid_reference(&raw.name, MAX_CLUSTER_REFERENCE_BYTES) && valid_reference(&raw.context, MAX_CLUSTER_REFERENCE_BYTES))
        .filter(|raw| valid_kubeconfig_path(&raw.kubeconfig_file))
        .map(|raw| Cluster {
            name: raw.name,
            kubeconfig_file: tenant_directory.join(raw.kubeconfig_file),
            context: raw.context,
        })
}


fn repeated<'a>(keys: impl Iterator<Item = (usize, &'a str)>) -> Vec<usize> {
    let mut seen: HashMap<&str, Vec<usize>> = HashMap::new();
    keys.for_each(|(index, key)| seen.entry(key).or_default().push(index));
    seen.into_values().filter(|indexes| indexes.len() > 1).flatten().collect()
}


/// The indexes of every entry whose context or name another entry also uses.
pub fn duplicated_indexes(entries: &[(usize, Cluster)]) -> Vec<usize> {
    let by_context = repeated(entries.iter().map(|(index, cluster)| (*index, cluster.context.as_str())));
    let by_name = repeated(entries.iter().map(|(index, cluster)| (*index, cluster.name.as_str())));
    by_context.into_iter().chain(by_name).collect()
}


/// A strict document: the cluster count is checked before any entry is built, a refused entry is counted by index and the others stay.
pub fn parse_declarations(text: &str, secrets_directory: &Path) -> Result<Declarations, DeclarationError> {
    let count = serde_saphyr::from_str::<ClusterCount>(text)
        .map_err(|_| DeclarationError::Malformed)?
        .clusters
        .len();
    if count > MAX_CLUSTERS {
        Err(DeclarationError::TooManyClusters { count, max: MAX_CLUSTERS })?;
    }
    let raw: RawDeclarations = serde_saphyr::from_str(text).map_err(|_| DeclarationError::Malformed)?;
    let tenant = tenant_scope(&raw.tenant).map_err(DeclarationError::Tenant)?;
    let tenant_directory = secrets_directory.join(tenant_of(&tenant));
    let parsed = raw
        .clusters
        .into_iter()
        .enumerate()
        .map(|(index, value)| (index, cluster_of(value, &tenant_directory)))
        .collect::<Vec<_>>();
    let mut refused = parsed
        .iter()
        .filter(|(_, cluster)| cluster.is_none())
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    let valid = parsed
        .into_iter()
        .filter_map(|(index, cluster)| cluster.map(|found| (index, found)))
        .collect::<Vec<_>>();
    let duplicated = duplicated_indexes(&valid);
    refused.extend(duplicated.iter().copied());
    refused.sort_unstable();
    refused.dedup();
    let clusters = valid
        .into_iter()
        .filter(|(index, _)| !duplicated.contains(index))
        .map(|(_, cluster)| cluster)
        .collect();
    Ok(Declarations { tenant, clusters, refused })
}


/// Reads at most `MAX_DECLARATION_BYTES` of the file, then `parse_declarations`.
pub fn load_declarations(path: &Path, secrets_directory: &Path) -> Result<Declarations, DeclarationError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_DECLARATION_BYTES + 1).read_to_end(&mut bytes))
        .map_err(DeclarationError::Read)?;
    if u64::try_from(bytes.len()).map_or(true, |read| read > MAX_DECLARATION_BYTES) {
        Err(DeclarationError::TooLarge { max: MAX_DECLARATION_BYTES })?;
    }
    let text = String::from_utf8(bytes).map_err(|_| DeclarationError::Malformed)?;
    parse_declarations(&text, secrets_directory)
}
