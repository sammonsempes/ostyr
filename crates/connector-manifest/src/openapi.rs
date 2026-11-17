use crate::bounded::{parameters, paths, schemes, servers};
use crate::bounded::{TOO_MANY_PARAMETERS, TOO_MANY_PATHS, TOO_MANY_SCHEMES, TOO_MANY_SERVERS};
use crate::error::ConnectorError;
use crate::model::{MAX_OPENAPI_PARAMETERS, MAX_OPENAPI_PATHS, MAX_OPENAPI_SCHEMES, MAX_OPENAPI_SERVERS};
use serde::Deserialize;


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
pub struct Operation {
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    #[serde(default, deserialize_with = "parameters")]
    pub parameters: Vec<Parameter>,
}


#[derive(Debug, Default, Deserialize)]
pub struct PathItem {
    pub get: Option<Operation>,
    pub put: Option<Operation>,
    pub post: Option<Operation>,
    pub delete: Option<Operation>,
    pub options: Option<Operation>,
    pub head: Option<Operation>,
    pub patch: Option<Operation>,
    pub trace: Option<Operation>,
    #[serde(default, deserialize_with = "parameters")]
    pub parameters: Vec<Parameter>,
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
pub struct Document {
    pub openapi: Option<String>,
    #[serde(default, deserialize_with = "paths")]
    pub paths: Vec<(String, PathItem)>,
    #[serde(default, deserialize_with = "servers")]
    pub servers: Vec<Server>,
    #[serde(default)]
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


/// Everything the generator does not use is skipped by the parser without being built; the version must be 3.0 or 3.1.
pub fn parse_document(bytes: &[u8]) -> Result<Document, ConnectorError> {
    let document: Document = serde_json::from_slice(bytes).map_err(|error| openapi_error(&error))?;
    let supported = document
        .openapi
        .as_deref()
        .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1."));
    supported.then_some(document).ok_or(ConnectorError::Invalid { field: "openapi" })
}
