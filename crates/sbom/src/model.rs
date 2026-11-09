//! Data model: limits, components, SBOMs and diffs.

use crate::limits::{DEFAULT_MAX_BYTES, DEFAULT_MAX_COMPONENTS, DEFAULT_MAX_DEPTH, DEFAULT_MAX_STRING_BYTES};
use vuln_match::model::Package;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_components: usize,
    pub max_depth: usize,
    pub max_string_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_components: DEFAULT_MAX_COMPONENTS,
            max_depth: DEFAULT_MAX_DEPTH,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub kind: String,
    pub purl: Option<String>,
    pub key: String,
    pub package: Option<Package>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sbom {
    pub tenant: String,
    pub artefact: String,
    pub components: Vec<Component>,
    pub skipped: usize,
    pub bad_purls: usize,
    pub unmapped: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSet {
    pub key: String,
    pub versions: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionChange {
    pub key: String,
    pub old_versions: Vec<String>,
    pub new_versions: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SbomDiff {
    pub added: Vec<VersionSet>,
    pub removed: Vec<VersionSet>,
    pub changed: Vec<VersionChange>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Root,
    Components,
    Component,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Partial {
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub kind: Option<String>,
    pub oversize: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub partial: Partial,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseState {
    pub stack: Vec<Frame>,
    pub sbom: Sbom,
    pub seen: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NoPurl,
    Malformed,
    Unmapped,
    Mapped,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub key: String,
    pub package: Option<Package>,
    pub outcome: Outcome,
}
