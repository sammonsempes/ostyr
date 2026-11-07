use secrecy::SecretString;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::PathBuf;


pub const IDENTITY_URI_PREFIX: &str = "urn:ostyr:agent:";


pub const MAX_IDENTITY_COMPONENT_LENGTH: usize = 64;


pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;


pub const ALPN_H2: &[u8] = b"h2";


pub const HEARTBEAT_PATH: &str = "/ostyr.agent.v1.Heartbeat/Beat";


/// Upper bound between a serial entering the revocation list and the close of that agent connections.
pub const REVOCATION_CLOSE_SECONDS: u64 = 5;


pub const PLACEHOLDER_ENDPOINT: &str = "http://agent-channel.invalid";


/// The agent identity, read from the verified client certificate and from nowhere else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub tenant: String,
    pub agent_id: String,
}


/// A private key in PEM form; `Debug` shows no key byte.
#[derive(Debug)]
pub struct PrivateKeyPem {
    pub pem: SecretString,
}


#[derive(Clone, Debug)]
pub struct ServerTlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub agent_ca: PathBuf,
}


#[derive(Clone, Debug)]
pub struct ClientTlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub platform_ca: PathBuf,
}


/// The revocation file as written: certificate serials in hexadecimal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocationFile {
    pub revoked_serials: Vec<String>,
}


/// Revoked certificate serials, lowercase hexadecimal without leading zeros.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawRevocationFile")]
pub struct Revocations {
    pub serials: BTreeSet<String>,
}
