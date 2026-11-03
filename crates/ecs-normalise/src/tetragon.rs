use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use time::OffsetDateTime;


#[derive(Debug, Deserialize)]
pub struct Envelope {
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub node_name: Option<String>,
    #[serde(flatten)]
    pub kinds: BTreeMap<String, Value>,
}


#[derive(Debug, Deserialize)]
pub struct Container {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}


#[derive(Debug, Deserialize)]
pub struct Pod {
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub name: String,
    pub container: Option<Container>,
}


#[derive(Debug, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub uid: Option<u32>,
    pub cwd: Option<String>,
    pub binary: String,
    pub arguments: Option<String>,
    pub pod: Option<Pod>,
}


#[derive(Debug, Deserialize)]
pub struct ProcessBody {
    pub process: Process,
    pub parent: Option<Process>,
}


#[derive(Debug, Deserialize)]
pub struct FileArg {
    pub path: String,
}


#[derive(Debug, Deserialize)]
pub struct SockArg {
    pub saddr: String,
    pub daddr: String,
    pub sport: u16,
    pub dport: u16,
}


#[derive(Debug, Deserialize)]
pub struct Arg {
    pub file_arg: Option<FileArg>,
    pub sock_arg: Option<SockArg>,
}


#[derive(Debug, Deserialize)]
pub struct KprobeBody {
    pub process: Process,
    pub parent: Option<Process>,
    pub function_name: String,
    #[serde(default)]
    pub args: Vec<Arg>,
}
