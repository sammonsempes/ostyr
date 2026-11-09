use crate::error::{InsertClass, InsertError};
use crate::model::Document;
use crate::settings::IngestSettings;
use crate::types::SinkFn;
use core_config::reload::{current_config, ReloadEngine};
use serde_json::{Map, Value};
use siem_schema::schema::{TENANT_COLUMN, TENANT_TIER_COLUMN};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use ureq::http::{HeaderMap, StatusCode};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;


pub const MAX_JSON_DEPTH: usize = 130;


pub const MAX_PASSWORD_BYTES: u64 = 4096;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const EXCEPTION_CODE_HEADER: &str = "X-ClickHouse-Exception-Code";


pub const USER_HEADER: &str = "X-ClickHouse-User";


pub const KEY_HEADER: &str = "X-ClickHouse-Key";


pub const PARSE_CODES: [u32; 8] = [6, 26, 27, 38, 41, 53, 117, 190];


/// Without a CA file the bundled web roots apply; with one, only that CA is trusted.
pub fn new_agent(ca_pem: Option<&[u8]>) -> Result<Agent, InsertError> {
    let builder = Agent::config_builder().http_status_as_error(false);
    let configured = match ca_pem {
        Some(pem) => {
            let certificate = Certificate::from_pem(pem).map_err(InsertError::CaInvalid)?;
            let tls = TlsConfig::builder().root_certs(RootCerts::Specific(Arc::new(vec![certificate]))).build();
            builder.tls_config(tls)
        }
        None => builder,
    };
    Ok(Agent::new_with_config(configured.build()))
}


pub fn join_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}


pub fn flatten_level(frontier: Vec<(String, Value)>, mut flat: Map<String, Value>) -> (Vec<(String, Value)>, Map<String, Value>) {
    let next = frontier
        .into_iter()
        .flat_map(|(prefix, value)| match value {
            Value::Object(object) => object
                .into_iter()
                .map(|(key, child)| (join_key(&prefix, &key), child))
                .collect::<Vec<_>>(),
            leaf => {
                flat.insert(prefix, leaf);
                Vec::new()
            }
        })
        .collect();
    (next, flat)
}


/// Nested objects become dotted keys, the column layout of the events table; one level per iteration, bounded by the JSON depth limit.
pub fn flatten_event(payload: &[u8]) -> Result<Map<String, Value>, serde_json::Error> {
    let root: Value = serde_json::from_slice(payload)?;
    let (_, flat) = (0..MAX_JSON_DEPTH).fold((vec![(String::new(), root)], Map::new()), |(frontier, flat), _| {
        flatten_level(frontier, flat)
    });
    Ok(flat)
}


/// One JSONEachRow line per document; the tenant column is the subject's, and the tier column can never come from the body.
pub fn render_rows(tenant: &str, documents: &[Document]) -> Result<Vec<u8>, serde_json::Error> {
    documents.iter().try_fold(Vec::new(), |mut body, document| {
        let mut row = flatten_event(&document.payload)?;
        row.remove(TENANT_TIER_COLUMN);
        row.insert(TENANT_COLUMN.to_owned(), Value::String(tenant.to_owned()));
        body.extend_from_slice(Value::Object(row).to_string().as_bytes());
        body.push(b'\n');
        Ok(body)
    })
}


/// Reads at most `MAX_PASSWORD_BYTES`; the trailing newline of a secret file is dropped.
pub fn read_secret<Source: Read>(reader: Source) -> Result<String, InsertError> {
    let mut text = String::new();
    reader
        .take(MAX_PASSWORD_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(InsertError::Credentials)?;
    if text.len() as u64 > MAX_PASSWORD_BYTES {
        Err(InsertError::CredentialsTooLarge)
    } else {
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }
}


/// Reads at most `MAX_CA_BYTES`.
pub fn read_ca<Source: Read>(reader: Source) -> Result<Vec<u8>, InsertError> {
    let mut bytes = Vec::new();
    reader.take(MAX_CA_BYTES + 1).read_to_end(&mut bytes).map_err(InsertError::CaFile)?;
    if bytes.len() as u64 > MAX_CA_BYTES {
        Err(InsertError::CaTooLarge)
    } else {
        Ok(bytes)
    }
}


/// The CA file is read again for every batch, so a swapped file applies from the next insert.
pub fn agent_for(settings: &IngestSettings) -> Result<Agent, InsertError> {
    let pem = settings
        .clickhouse_ca_file
        .as_deref()
        .map(|path| read_ca(File::open(path).map_err(InsertError::CaFile)?))
        .transpose()?;
    new_agent(pem.as_deref())
}


pub fn read_password(path: &Path) -> Result<String, InsertError> {
    read_secret(File::open(path).map_err(InsertError::Credentials)?)
}


/// The server's own message is never read: only the status and the numeric exception code pick the class.
pub fn failure_class(status: StatusCode, exception_code: Option<u32>) -> InsertClass {
    if exception_code.is_some_and(|code| PARSE_CODES.contains(&code)) {
        InsertClass::ParseError
    } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        InsertClass::Unauthorized
    } else if status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::GATEWAY_TIMEOUT {
        InsertClass::Timeout
    } else if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        InsertClass::Unavailable
    } else {
        InsertClass::Rejected
    }
}


pub fn classify_reply(status: StatusCode, exception_code: Option<u32>) -> Option<InsertClass> {
    (!status.is_success()).then(|| failure_class(status, exception_code))
}


pub fn classify_transport(error: &ureq::Error) -> InsertClass {
    if matches!(error, ureq::Error::Timeout(_)) {
        InsertClass::Timeout
    } else {
        InsertClass::Unavailable
    }
}


/// A missing or non-numeric header means no usable code: the class then comes from the status alone.
pub fn exception_code(headers: &HeaderMap) -> Option<u32> {
    headers
        .get(EXCEPTION_CODE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse().ok())
}


pub fn insert_query(settings: &IngestSettings) -> String {
    format!("INSERT INTO `{}` FORMAT JSONEachRow", settings.clickhouse_table)
}


/// One request with a global deadline from the settings; the table and database were validated as identifiers.
pub fn insert_rows(agent: &Agent, settings: &IngestSettings, password: &str, body: Vec<u8>) -> Result<(), InsertError> {
    let reply = agent
        .post(&settings.clickhouse_url)
        .query("query", insert_query(settings))
        .query("database", &settings.clickhouse_database)
        .query("input_format_skip_unknown_fields", "1")
        .query("date_time_input_format", "best_effort")
        .header(USER_HEADER, &settings.clickhouse_user)
        .header(KEY_HEADER, password)
        .config()
        .timeout_global(Some(Duration::from_millis(settings.insert_timeout_ms)))
        .http_status_as_error(false)
        .build()
        .send(body);
    let class = match reply {
        Ok(response) => classify_reply(response.status(), exception_code(response.headers())),
        Err(error) => Some(classify_transport(&error)),
    };
    class.map_or(Ok(()), |failed| Err(InsertError::Class(failed)))
}


/// The sink for the batcher: one settings snapshot, one password read and one CA read per call, so a live swap applies from the next batch.
pub fn clickhouse_sink(settings: Arc<ReloadEngine<IngestSettings>>) -> Box<SinkFn> {
    Box::new(move |tenant, documents| {
        let snapshot = current_config(&settings);
        let password = read_password(&snapshot.clickhouse_password_file)?;
        let body = render_rows(tenant, documents).map_err(|error| {
            warn!(class = ?error.classify(), "an event could not be rendered as a row");
            InsertError::Class(InsertClass::ParseError)
        })?;
        let agent = agent_for(&snapshot)?;
        insert_rows(&agent, &snapshot, &password, body)?;
        Ok(())
    })
}
