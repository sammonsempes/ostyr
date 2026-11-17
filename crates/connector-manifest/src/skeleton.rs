use crate::error::ConnectorError;
use crate::manifest::{check, parse_manifest, valid_name};
use crate::model::{
    MANIFEST_NAME, MAX_ACTIONS, MAX_OPENAPI_BYTES, MAX_OPENAPI_OPERATIONS, MAX_PATH_BYTES, MAX_URL_BYTES, OPERATIONS_NAME, SKELETON_VERSION,
};
use crate::openapi::{parse_document, Document, Operation, Parameter, PathItem, Scheme};
use crate::package::{io_at, io_error, read_capped};
use crate::types::WriteFn;
use crate::verify::write_all_bytes;
use std::collections::BTreeSet;
use std::fs::{DirBuilder, File};
use std::io;
use std::path::Path;
use tempfile::NamedTempFile;


pub const LOCATIONS: [&str; 4] = ["query", "path", "header", "cookie"];


pub const METHODS: [&str; 8] = ["delete", "get", "head", "options", "patch", "post", "put", "trace"];


pub const SECRET_SCHEME_TYPES: [&str; 2] = ["http", "apiKey"];


pub const READ_SCOPE: &str = "api:read";


pub const WRITE_SCOPE: &str = "api:write";


pub const SECRET_PREFIX: &str = "secret_";


#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    pub method: &'static str,
    pub path: &'a str,
    pub id: Option<&'a str>,
    pub parameters: Vec<&'a Parameter>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub method: &'static str,
    pub path: String,
    pub name: String,
    pub parameters: BTreeSet<(String, String)>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub operations: usize,
    pub bad_path: usize,
    pub bad_operation_id: usize,
    pub bad_parameter: usize,
    pub bad_server: usize,
    pub bad_scheme: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    pub manifest: String,
    pub operations: String,
    pub summary: Summary,
}


pub fn path_character(character: char) -> bool {
    matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '{' | '}' | '.' | '_' | '~' | '-')
}


/// An ASCII allowlist, rooted, with no `.` or `..` segment.
pub fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_BYTES
        && path.chars().all(path_character)
        && path.split('/').all(|segment| segment != "." && segment != "..")
}


pub fn url_character(character: char) -> bool {
    matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '~' | ':' | '/' | '@' | '-')
}


pub fn valid_url(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://")) && url.len() <= MAX_URL_BYTES && url.chars().all(url_character)
}


pub fn path_operations(item: &PathItem) -> Vec<(&'static str, &Operation)> {
    [
        ("delete", &item.delete),
        ("get", &item.get),
        ("head", &item.head),
        ("options", &item.options),
        ("patch", &item.patch),
        ("post", &item.post),
        ("put", &item.put),
        ("trace", &item.trace),
    ]
    .into_iter()
    .filter_map(|(method, operation)| operation.as_ref().map(|found| (method, found)))
    .collect()
}


/// The operations of the valid paths in path order, and the number of operations skipped for a bad path.
pub fn candidates(document: &Document) -> Result<(Vec<Candidate<'_>>, usize), ConnectorError> {
    let mut sorted: Vec<&(String, PathItem)> = document.paths.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let (valid, invalid): (Vec<_>, Vec<_>) = sorted.into_iter().partition(|entry| valid_path(&entry.0));
    let bad_path = invalid.iter().map(|entry| path_operations(&entry.1).len()).sum();
    let found: Vec<Candidate<'_>> = valid
        .into_iter()
        .flat_map(|entry| {
            let (path, item) = entry;
            path_operations(item).into_iter().map(move |(method, operation)| Candidate {
                method,
                path: path.as_str(),
                id: operation.operation_id.as_deref(),
                parameters: item.parameters.iter().chain(operation.parameters.iter()).collect(),
            })
        })
        .collect();
    (found.len() <= MAX_OPENAPI_OPERATIONS)
        .then_some((found, bad_path))
        .ok_or(ConnectorError::OpenApiBound {
            bound: "operations",
            max: MAX_OPENAPI_OPERATIONS,
        })
}


/// A name shaped like a generated `<method>_<n>` is never taken from the document, so a generated name cannot collide.
pub fn fallback_shape(name: &str) -> bool {
    name.split_once('_')
        .is_some_and(|(method, rest)| METHODS.contains(&method) && !rest.is_empty() && rest.chars().all(|character| character.is_ascii_digit()))
}


pub fn next_name(candidate: &Candidate<'_>, index: usize, used: &BTreeSet<String>) -> String {
    let usable = candidate
        .id
        .map(str::to_ascii_lowercase)
        .filter(|name| valid_name(name) && !fallback_shape(name) && !used.contains(name));
    usable.unwrap_or_else(|| format!("{}_{}", candidate.method, index + 1))
}


pub fn assign_names(candidates: &[Candidate<'_>]) -> Vec<String> {
    candidates
        .iter()
        .enumerate()
        .fold((Vec::new(), BTreeSet::new()), |(mut names, mut used), (index, candidate)| {
            let name = next_name(candidate, index, &used);
            used.insert(name.clone());
            names.push(name);
            (names, used)
        })
        .0
}


pub fn parameter_key(parameter: &Parameter) -> Option<(String, String)> {
    parameter
        .name
        .clone()
        .zip(parameter.location.clone())
        .filter(|(name, location)| valid_name(name) && LOCATIONS.contains(&location.as_str()))
}


pub fn plan(candidates: &[Candidate<'_>]) -> (Vec<Planned>, Summary) {
    let names = assign_names(candidates);
    let planned: Vec<Planned> = candidates
        .iter()
        .zip(names)
        .map(|(candidate, name)| Planned {
            method: candidate.method,
            path: candidate.path.to_owned(),
            name,
            parameters: candidate.parameters.iter().filter_map(|parameter| parameter_key(parameter)).collect(),
        })
        .collect();
    let bad_parameter = candidates
        .iter()
        .map(|candidate| candidate.parameters.iter().filter(|parameter| parameter_key(parameter).is_none()).count())
        .sum();
    let bad_operation_id = candidates
        .iter()
        .filter(|candidate| candidate.id.is_some_and(|id| !valid_name(&id.to_ascii_lowercase())))
        .count();
    let summary = Summary {
        operations: planned.len(),
        bad_parameter,
        bad_operation_id,
        ..Summary::default()
    };
    (planned, summary)
}


/// The vendor URLs that pass the grammar, sorted, and how many were refused.
pub fn server_urls(document: &Document) -> (BTreeSet<String>, usize) {
    let urls: BTreeSet<String> = document
        .servers
        .iter()
        .filter_map(|server| server.url.as_deref())
        .filter(|url| valid_url(url))
        .map(str::to_owned)
        .collect();
    (urls.clone(), document.servers.len() - urls.len())
}


/// One `secret_file` field name per `http` or `apiKey` scheme; any other, bad or duplicate scheme is counted.
pub fn secret_fields(document: &Document) -> (BTreeSet<String>, usize) {
    let schemes: &Vec<(String, Scheme)> = &document.components.security_schemes;
    let names: BTreeSet<String> = schemes
        .iter()
        .filter(|(_, scheme)| scheme.kind.as_deref().is_some_and(|kind| SECRET_SCHEME_TYPES.contains(&kind)))
        .map(|(key, _)| format!("{SECRET_PREFIX}{}", key.to_ascii_lowercase()))
        .filter(|name| valid_name(name))
        .collect();
    (names.clone(), schemes.len() - names.len())
}


pub fn section(key: &str, items: &[String]) -> String {
    match items.is_empty() {
        true => format!("{key}: []\n"),
        false => format!("{key}:\n{}\n", items.join("\n")),
    }
}


pub fn action_item(planned: &Planned) -> String {
    let scope = if planned.method == "get" { READ_SCOPE } else { WRITE_SCOPE };
    format!("  - name: {}\n    targets: [{scope}]\n    default_approval: human", planned.name)
}


pub fn field_item(name: &str, kind: &str) -> String {
    format!("  - name: {name}\n    kind: {kind}\n    required: true")
}


pub fn render_manifest(name: &str, publisher: &str, planned: &[Planned], secrets: &BTreeSet<String>) -> String {
    let actions: Vec<String> = planned.iter().map(action_item).collect();
    let fields: Vec<String> = std::iter::once(field_item("base_url", "string"))
        .chain(secrets.iter().map(|secret| field_item(secret, "secret_file")))
        .collect();
    format!(
        "name: {name}\nversion: {SKELETON_VERSION}\npublisher: {publisher}\nrights: []\n{}{}",
        section("actions", &actions),
        section("config", &fields)
    )
}


pub fn operation_item(planned: &Planned) -> String {
    let parameters: Vec<String> = planned
        .parameters
        .iter()
        .map(|(name, location)| format!("      - name: {name}\n        in: {location}"))
        .collect();
    let listed = if parameters.is_empty() {
        "    parameters: []".to_owned()
    } else {
        format!("    parameters:\n{}", parameters.join("\n"))
    };
    format!(
        "  - method: {}\n    path: \"{}\"\n    operation: {}\n{listed}",
        planned.method, planned.path, planned.name
    )
}


pub fn render_operations(urls: &BTreeSet<String>, planned: &[Planned]) -> String {
    let servers: Vec<String> = urls.iter().map(|url| format!("  - \"{url}\"")).collect();
    let operations: Vec<String> = planned.iter().map(operation_item).collect();
    format!("{}{}", section("servers", &servers), section("operations", &operations))
}


/// The draft package texts; the manifest is validated before anything exists on disk.
pub fn build_skeleton(document: &Document, name: &str, publisher: &str) -> Result<Skeleton, ConnectorError> {
    check(valid_name(name), "name")?;
    check(valid_name(publisher), "publisher")?;
    let (found, bad_path) = candidates(document)?;
    let (planned, summary) = plan(&found);
    (planned.len() <= MAX_ACTIONS).then_some(()).ok_or(ConnectorError::OpenApiBound {
        bound: "actions",
        max: MAX_ACTIONS,
    })?;
    let (urls, bad_server) = server_urls(document);
    let (secrets, bad_scheme) = secret_fields(document);
    let manifest = render_manifest(name, publisher, &planned, &secrets);
    parse_manifest(manifest.as_bytes())?;
    Ok(Skeleton {
        manifest,
        operations: render_operations(&urls, &planned),
        summary: Summary {
            bad_path,
            bad_server,
            bad_scheme,
            ..summary
        },
    })
}


pub fn summary_line(summary: &Summary) -> String {
    format!(
        "skeleton operations={} bad_path={} bad_operation_id={} bad_parameter={} bad_server={} bad_scheme={}",
        summary.operations, summary.bad_path, summary.bad_operation_id, summary.bad_parameter, summary.bad_server, summary.bad_scheme
    )
}


/// The document is read through a capped read before any parse.
pub fn skeleton_from_file(openapi: &Path, name: &str, publisher: &str) -> Result<Skeleton, ConnectorError> {
    let label = openapi.display().to_string();
    let mut file = File::open(openapi).map_err(io_at(&label))?;
    let bytes = read_capped(&mut file, MAX_OPENAPI_BYTES, &label)?;
    build_skeleton(&parse_document(&bytes)?, name, publisher)
}


/// `mkdir` fails on any existing name, a symbolic link included, so there is no check-then-create window.
#[cfg(unix)]
pub fn create_directory(path: &Path) -> io::Result<()> {
    use crate::model::DIRECTORY_MODE;
    use std::os::unix::fs::DirBuilderExt;
    DirBuilder::new().mode(DIRECTORY_MODE).create(path)
}


#[cfg(not(unix))]
pub fn create_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().create(path)
}


/// Staged in the new directory and renamed to its name; the writer is injected to test an interrupted write.
pub fn write_staged_with(writer: WriteFn, directory: &Path, name: &str, text: &str) -> Result<(), ConnectorError> {
    let target = directory.join(name);
    let label = target.display().to_string();
    let mut staged = NamedTempFile::new_in(directory).map_err(io_at(&label))?;
    writer(staged.as_file_mut(), text.as_bytes()).map_err(io_at(&label))?;
    staged.persist(&target).map(|_| ()).map_err(|error| io_error(&label, error.error))
}


pub fn write_skeleton_with(writer: WriteFn, directory: &Path, skeleton: &Skeleton) -> Result<(), ConnectorError> {
    create_directory(directory).map_err(io_at(&directory.display().to_string()))?;
    write_staged_with(writer, directory, MANIFEST_NAME, &skeleton.manifest)?;
    write_staged_with(writer, directory, OPERATIONS_NAME, &skeleton.operations)
}


pub fn write_skeleton(directory: &Path, skeleton: &Skeleton) -> Result<(), ConnectorError> {
    write_skeleton_with(write_all_bytes, directory, skeleton)
}
