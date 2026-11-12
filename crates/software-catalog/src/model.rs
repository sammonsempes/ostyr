//! Data only.

use serde::Deserialize;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Apt(String),
    Dnf(String),
    Winget(String),
    Msi(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Version {
    Pinned(String),
    LatestApproved(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub source: Source,
    pub version: Version,
    pub sha256: Option<String>,
    pub publisher: String,
    #[serde(default)]
    pub uninstall: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    pub entries: Vec<Entry>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    #[serde(default)]
    pub install: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Manager {
    Apt,
    Dnf,
    Winget,
    Msi,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRow {
    pub manager: Manager,
    pub package: String,
    pub version: String,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installed {
    pub rows: Vec<InstalledRow>,
    pub malformed: usize,
    pub over_limit: usize,
    pub not_installed: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Row(InstalledRow),
    NotInstalled,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionKind {
    Install,
    Update,
    Uninstall,
    NewerThanCatalogue,
    Unknown,
    NotInCatalogue,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub kind: ActionKind,
    pub name: String,
    pub package: String,
    pub installed_version: Option<String>,
    pub target_version: Option<String>,
    pub arguments: Vec<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub refused_uninstalls: Vec<String>,
}
