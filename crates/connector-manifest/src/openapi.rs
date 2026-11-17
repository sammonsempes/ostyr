use crate::bounded::{parameters, paths, schemes, servers, Bounded};
use crate::error::ConnectorError;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::value::RawValue;


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
    pub parameters: Bounded<Box<RawValue>>,
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
    pub parameters: Bounded<Box<RawValue>>,
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
pub struct RawComponents {
    #[serde(default, rename = "securitySchemes", deserialize_with = "schemes")]
    pub security_schemes: Bounded<(String, Box<RawValue>)>,
}


#[derive(Debug, Default)]
pub struct Components {
    pub security_schemes: Vec<(String, Option<Scheme>)>,
}


#[derive(Debug, Default, Deserialize)]
pub struct RawDocument {
    pub openapi: Option<String>,
    #[serde(default, deserialize_with = "paths")]
    pub paths: Bounded<(String, Box<RawValue>)>,
    #[serde(default, deserialize_with = "servers")]
    pub servers: Bounded<Box<RawValue>>,
    #[serde(default)]
    pub components: RawComponents,
}


#[derive(Debug, Default)]
pub struct Document {
    pub openapi: Option<String>,
    pub paths: Vec<(String, Option<PathItem>)>,
    pub servers: Vec<Option<Server>>,
    pub components: Components,
}


/// Any parser failure is its category, line and column, never a byte of the document and never a bound.
pub fn openapi_error(error: &serde_json::Error) -> ConnectorError {
    ConnectorError::OpenApi {
        category: format!("{:?}", error.classify()),
        line: error.line(),
        column: error.column(),
    }
}


/// A bound hit of a document-level collection refuses the document, named by the typed outcome.
pub fn within<Element>(bounded: Bounded<Element>, bound: &'static str) -> Result<Vec<Element>, ConnectorError> {
    match bounded {
        Bounded::Within(items) => Ok(items),
        Bounded::Over { limit } => Err(ConnectorError::OpenApiBound { bound, max: limit }),
    }
}


/// One element that does not parse is `None` (skipped and counted by the caller); only its category is logged.
pub fn lenient<Raw: DeserializeOwned>(raw: &RawValue) -> Option<Raw> {
    match serde_json::from_str::<Raw>(raw.get()) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            let category = format!("{:?}", error.classify());
            log::debug!("skipped one OpenAPI element: {category}");
            None
        }
    }
}


/// A list over its bound makes the owner of the list `None`, never the whole document.
pub fn parameter_slots(bounded: Bounded<Box<RawValue>>) -> Option<Vec<Option<Parameter>>> {
    match bounded {
        Bounded::Within(raws) => Some(raws.iter().map(|raw| lenient::<Parameter>(raw)).collect()),
        Bounded::Over { .. } => None,
    }
}


pub fn resolve_operation(raw: &RawValue) -> Option<Operation> {
    lenient::<RawOperation>(raw).and_then(|parsed| {
        parameter_slots(parsed.parameters).map(|parameters| Operation {
            operation_id: parsed.operation_id,
            parameters,
        })
    })
}


pub fn resolve_item(raw: &RawValue) -> Option<PathItem> {
    lenient::<RawItem>(raw).and_then(|parsed| {
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
            .filter_map(|(method, found)| found.map(|raw_operation| (method, resolve_operation(&raw_operation))))
            .collect();
        parameter_slots(parsed.parameters).map(|parameters| PathItem { operations, parameters })
    })
}


/// Everything the generator does not use is skipped by the parser without being built; the version must be 3.0 or 3.1.
pub fn parse_document(bytes: &[u8]) -> Result<Document, ConnectorError> {
    let raw: RawDocument = serde_json::from_slice(bytes).map_err(|error| openapi_error(&error))?;
    let supported = raw
        .openapi
        .as_deref()
        .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1."));
    supported.then_some(()).ok_or(ConnectorError::Invalid { field: "openapi" })?;
    let paths = within(raw.paths, "paths")?
        .iter()
        .map(|(path, item)| (path.clone(), resolve_item(item)))
        .collect();
    Ok(Document {
        openapi: raw.openapi,
        paths,
        servers: within(raw.servers, "servers")?
            .iter()
            .map(|raw_server| lenient::<Server>(raw_server))
            .collect(),
        components: Components {
            security_schemes: within(raw.components.security_schemes, "security schemes")?
                .into_iter()
                .map(|(key, raw_scheme)| (key, lenient::<Scheme>(&raw_scheme)))
                .collect(),
        },
    })
}
