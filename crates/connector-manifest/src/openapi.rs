use crate::bounded::{parameters, paths, schemes, servers};
use crate::bounded::{TOO_MANY_PARAMETERS, TOO_MANY_PATHS, TOO_MANY_SCHEMES, TOO_MANY_SERVERS};
use crate::error::ConnectorError;
use crate::model::{MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES, MAX_OPENAPI_SERVERS};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::value::RawValue;


/// The bounds a document can hit while parsing: the fixed message of the bounded reader, the name shown, the cap.
pub const OPENAPI_BOUNDS: [(&str, &str, usize); 4] = [
    (TOO_MANY_PATHS, "paths", MAX_OPENAPI_PATHS),
    (TOO_MANY_PARAMETERS, "parameters", MAX_OPENAPI_PARAMETERS),
    (TOO_MANY_SCHEMES, "security schemes", MAX_OPENAPI_SCHEMES),
    (TOO_MANY_SERVERS, "servers", MAX_OPENAPI_SERVERS),
];


#[derive(Debug, Default, Deserialize)]
pub struct Parameter {
    pub name: Option<String>,
    #[serde(rename = "in")]
    pub location: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct RawOperation {
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "parameters")]
    pub parameters: Vec<Box<RawValue>>,
}


#[derive(Debug, Default, Deserialize)]
pub struct RawItem {
    pub get: Option<Box<RawValue>>,
    pub put: Option<Box<RawValue>>,
    pub post: Option<Box<RawValue>>,
    pub delete: Option<Box<RawValue>>,
    pub options: Option<Box<RawValue>>,
    pub head: Option<Box<RawValue>>,
    pub patch: Option<Box<RawValue>>,
    pub trace: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "parameters")]
    pub parameters: Vec<Box<RawValue>>,
}


/// An element of the wrong JSON type is `None`: skipped alone and counted by the caller.
#[derive(Debug, Default)]
pub struct Operation {
    pub operation_id: Option<String>,
    pub parameters: Vec<Option<Parameter>>,
}


#[derive(Debug, Default)]
pub struct PathItem {
    pub operations: Vec<(&'static str, Option<Operation>)>,
    pub parameters: Vec<Option<Parameter>>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Server {
    pub url: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Scheme {
    #[serde(rename = "type")]
    pub kind: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Components {
    #[serde(default, rename = "securitySchemes", deserialize_with = "schemes")]
    pub security_schemes: Vec<(String, Scheme)>,
}


#[derive(Debug, Default, Deserialize)]
pub struct RawDocument {
    pub openapi: Option<String>,
    #[serde(default, deserialize_with = "paths")]
    pub paths: Vec<(String, Box<RawValue>)>,
    #[serde(default, deserialize_with = "servers")]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub components: Components,
}


#[derive(Debug, Default)]
pub struct Document {
    pub openapi: Option<String>,
    pub paths: Vec<(String, Option<PathItem>)>,
    pub servers: Vec<Server>,
    pub components: Components,
}


/// A bound hit is named; any other failure is its category, line and column, never a byte of the document.
pub fn openapi_error(error: &serde_json::Error) -> ConnectorError {
    let text = error.to_string();
    OPENAPI_BOUNDS.iter().find(|(message, _, _)| text.contains(message)).map_or_else(
        || ConnectorError::OpenApi {
            category: format!("{:?}", error.classify()),
            line: error.line(),
            column: error.column(),
        },
        |(_, bound, max)| ConnectorError::OpenApiBound { bound, max: *max },
    )
}


/// A bound hit refuses the document; any other failure of one element only skips it (`None`).
pub fn lenient<Raw: DeserializeOwned>(raw: &RawValue) -> Result<Option<Raw>, ConnectorError> {
    match serde_json::from_str::<Raw>(raw.get()) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) => match openapi_error(&error) {
            bound @ ConnectorError::OpenApiBound { .. } => Err(bound),
            _ => Ok(None),
        },
    }
}


pub fn parameter_slots(raws: &[Box<RawValue>]) -> Result<Vec<Option<Parameter>>, ConnectorError> {
    raws.iter().map(|raw| lenient::<Parameter>(raw)).collect()
}


pub fn resolve_operation(raw: &RawValue) -> Result<Option<Operation>, ConnectorError> {
    lenient::<RawOperation>(raw)?
        .map(|parsed| {
            parameter_slots(&parsed.parameters).map(|parameters| Operation {
                operation_id: parsed.operation_id,
                parameters,
            })
        })
        .transpose()
}


pub fn resolve_item(raw: &RawValue) -> Result<Option<PathItem>, ConnectorError> {
    lenient::<RawItem>(raw)?
        .map(|parsed| {
            let methods = [
                ("delete", parsed.delete),
                ("get", parsed.get),
                ("head", parsed.head),
                ("options", parsed.options),
                ("patch", parsed.patch),
                ("post", parsed.post),
                ("put", parsed.put),
                ("trace", parsed.trace),
            ];
            let operations = methods
                .into_iter()
                .filter_map(|(method, found)| found.map(|raw_operation| resolve_operation(&raw_operation).map(|operation| (method, operation))))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PathItem {
                operations,
                parameters: parameter_slots(&parsed.parameters)?,
            })
        })
        .transpose()
}


/// Everything the generator does not use is skipped by the parser without being built; the version must be 3.0 or 3.1.
pub fn parse_document(bytes: &[u8]) -> Result<Document, ConnectorError> {
    let raw: RawDocument = serde_json::from_slice(bytes).map_err(|error| openapi_error(&error))?;
    let supported = raw
        .openapi
        .as_deref()
        .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1."));
    supported.then_some(()).ok_or(ConnectorError::Invalid { field: "openapi" })?;
    let paths = raw
        .paths
        .iter()
        .map(|(path, item)| resolve_item(item).map(|resolved| (path.clone(), resolved)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Document {
        openapi: raw.openapi,
        paths,
        servers: raw.servers,
        components: raw.components,
    })
}
