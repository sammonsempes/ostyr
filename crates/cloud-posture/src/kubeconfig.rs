use crate::model::KubeconfigFault;
use core_config::strict::{refuse_features, refuse_forbidden_bytes, Rules};
use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::fs::File;
use std::io::{self, Read, Write};


pub const MAX_KUBECONFIG_BYTES: u64 = 65_536;


pub const MAX_ENTRIES: usize = 64;


pub const FILE_LABEL: &str = "kubeconfig";


pub const MEMFD_NAME: &str = "kubeconfig";


pub const RULES: Rules<'static> = Rules {
    list_key: "clusters",
    invalid_text: "invalid",
    allow_flow: true,
    show_line: false,
};


#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Counts {
    pub clusters: Option<Vec<IgnoredAny>>,
    pub users: Option<Vec<IgnoredAny>>,
    pub contexts: Option<Vec<IgnoredAny>>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "apiVersion")]
    pub api_version: Option<IgnoredAny>,
    pub kind: Option<IgnoredAny>,
    pub preferences: Option<Preferences>,
    pub clusters: Option<Vec<NamedCluster>>,
    pub users: Option<Vec<NamedUser>>,
    pub contexts: Option<Vec<NamedContext>>,
    #[serde(rename = "current-context")]
    pub current_context: Option<IgnoredAny>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCluster {
    pub name: Option<IgnoredAny>,
    pub cluster: ClusterBody,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterBody {
    pub server: Option<IgnoredAny>,
    #[serde(rename = "certificate-authority-data")]
    pub certificate_authority_data: Option<IgnoredAny>,
    #[serde(rename = "tls-server-name")]
    pub tls_server_name: Option<IgnoredAny>,
    #[serde(rename = "certificate-authority")]
    pub certificate_authority: Option<IgnoredAny>,
    #[serde(rename = "proxy-url")]
    pub proxy_url: Option<IgnoredAny>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedUser {
    pub name: Option<IgnoredAny>,
    pub user: UserBody,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserBody {
    pub token: Option<IgnoredAny>,
    #[serde(rename = "client-certificate-data")]
    pub client_certificate_data: Option<IgnoredAny>,
    #[serde(rename = "client-key-data")]
    pub client_key_data: Option<IgnoredAny>,
    pub exec: Option<IgnoredAny>,
    #[serde(rename = "auth-provider")]
    pub auth_provider: Option<IgnoredAny>,
    #[serde(rename = "client-certificate")]
    pub client_certificate: Option<IgnoredAny>,
    #[serde(rename = "client-key")]
    pub client_key: Option<IgnoredAny>,
    #[serde(rename = "tokenFile")]
    pub token_file: Option<IgnoredAny>,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedContext {
    pub name: Option<IgnoredAny>,
    pub context: ContextBody,
}


#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBody {
    pub cluster: Option<IgnoredAny>,
    pub user: Option<IgnoredAny>,
    pub namespace: Option<IgnoredAny>,
}


/// At most `MAX_KUBECONFIG_BYTES` from the checked handle, read once; more is `TooLarge`, a read error `Unreadable`.
pub fn read_checked(reader: &mut dyn Read) -> Result<Vec<u8>, KubeconfigFault> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_KUBECONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KubeconfigFault::Unreadable)?;
    if u64::try_from(bytes.len()).map_or(true, |read| read > MAX_KUBECONFIG_BYTES) {
        Err(KubeconfigFault::TooLarge)
    } else {
        Ok(bytes)
    }
}


/// The first forbidden key of a cluster entry: a file path or a proxy.
pub fn cluster_fault(body: &ClusterBody) -> Option<KubeconfigFault> {
    body.certificate_authority
        .is_some()
        .then_some(KubeconfigFault::FilePath)
        .or(body.proxy_url.is_some().then_some(KubeconfigFault::ProxyUrl))
}


/// The first forbidden key of a user entry: a command, a plugin or a file path.
pub fn user_fault(body: &UserBody) -> Option<KubeconfigFault> {
    body.exec
        .is_some()
        .then_some(KubeconfigFault::Exec)
        .or(body.auth_provider.is_some().then_some(KubeconfigFault::AuthProvider))
        .or(body.client_certificate.is_some().then_some(KubeconfigFault::FilePath))
        .or(body.client_key.is_some().then_some(KubeconfigFault::FilePath))
        .or(body.token_file.is_some().then_some(KubeconfigFault::FilePath))
}


/// Every list holds at most `MAX_ENTRIES`, counted on zero-sized elements before any entry is built.
pub fn count_fault(counts: &Counts) -> Option<KubeconfigFault> {
    [&counts.clusters, &counts.users, &counts.contexts]
        .iter()
        .any(|list| list.as_ref().is_some_and(|entries| entries.len() > MAX_ENTRIES))
        .then_some(KubeconfigFault::TooMany)
}


/// The kubeconfig bytes against the allowlist: ASCII bytes, no YAML tag, anchor, alias, merge key, escape or block scalar, only the allowed keys.
pub fn check_content(bytes: &[u8]) -> Result<(), KubeconfigFault> {
    let text = std::str::from_utf8(bytes).map_err(|_| KubeconfigFault::Bytes)?;
    refuse_forbidden_bytes(text, FILE_LABEL).map_err(|_| KubeconfigFault::Bytes)?;
    refuse_features(text, FILE_LABEL, RULES).map_err(|_| KubeconfigFault::Bytes)?;
    let counts: Counts = serde_saphyr::from_str(text).map_err(|_| KubeconfigFault::Shape)?;
    count_fault(&counts).map_or(Ok(()), Err)?;
    let config: Config = serde_saphyr::from_str(text).map_err(|_| KubeconfigFault::Shape)?;
    let found = config
        .clusters
        .iter()
        .flatten()
        .find_map(|entry| cluster_fault(&entry.cluster))
        .or_else(|| config.users.iter().flatten().find_map(|entry| user_fault(&entry.user)));
    found.map_or(Ok(()), Err)
}


/// An empty memfd that accepts seals.
pub fn create_memfd() -> Result<File, io::Error> {
    memfd_create(MEMFD_NAME, MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC)
        .map(File::from)
        .map_err(io::Error::from)
}


/// All the bytes, written at the start of the file.
pub fn write_bytes(file: &mut File, bytes: &[u8]) -> Result<(), io::Error> {
    file.write_all(bytes)
}


/// No write, shrink, grow or further seal.
pub fn add_seals(file: &File) -> Result<(), io::Error> {
    fcntl_add_seals(file, SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL).map_err(io::Error::from)
}


/// The three steps of the sealing, injected so a test can fail each.
pub fn seal_with(
    create: fn() -> Result<File, io::Error>,
    write: fn(&mut File, &[u8]) -> Result<(), io::Error>,
    seal: fn(&File) -> Result<(), io::Error>,
    bytes: &[u8],
) -> Result<File, io::Error> {
    let mut file = create()?;
    write(&mut file, bytes)?;
    seal(&file)?;
    Ok(file)
}


/// The checked bytes in a sealed memfd: the child reads exactly them, whatever happens to the file.
pub fn seal_bytes(bytes: &[u8]) -> Result<File, io::Error> {
    seal_with(create_memfd, write_bytes, add_seals, bytes)
}
