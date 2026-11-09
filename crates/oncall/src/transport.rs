use crate::error::TransportError;
use crate::load::read_file_limited;
use crate::model::{Channel, ChannelKind, Message};
use crate::secret::read_secret;
use crate::settings::TransportSettings;
use crate::types::Headers;
use core_config::reload::{current_config, ReloadEngine};
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use ureq::config::Config;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;
use url::Url;
use zeroize::Zeroizing;


pub const FORBIDDEN_CHARS: [char; 4] = ['\u{2028}', '\u{2029}', '\u{0085}', '\0'];


pub const JSON_TYPE: &str = "application/json";


pub const TEXT_TYPE: &str = "text/plain; charset=utf-8";


/// What goes on the wire: a content type, a body and extra headers (a secret one is zeroised on drop).
pub struct Payload {
    pub content_type: &'static str,
    pub body: String,
    pub headers: Headers,
}


/// Line and paragraph separators, NEL and NUL are refused in every kind: parsers disagree on them.
pub fn check_text(message: &Message) -> Result<(), TransportError> {
    if message.subject.contains(FORBIDDEN_CHARS) || message.body.contains(FORBIDDEN_CHARS) {
        Err(TransportError::ForbiddenChar)
    } else {
        Ok(())
    }
}


/// The URL the request goes to is the parsed one, never the raw target text (`Url::parse` strips tabs and line breaks).
pub fn https_url(channel: &Channel) -> Result<Url, TransportError> {
    match Url::parse(&channel.target) {
        Ok(url) if url.scheme() == "https" => Ok(url),
        _ => Err(TransportError::Target),
    }
}


pub fn payload(kind: ChannelKind, message: &Message) -> Result<Payload, TransportError> {
    let text = format!("{}\n{}", message.subject, message.body);
    match kind {
        ChannelKind::Smtp => Err(TransportError::NotHttps),
        ChannelKind::Webhook => Ok(Payload {
            content_type: JSON_TYPE,
            body: message.body.clone(),
            headers: Vec::new(),
        }),
        ChannelKind::Ntfy => Ok(Payload {
            content_type: TEXT_TYPE,
            body: message.body.clone(),
            headers: vec![("Title", Zeroizing::new(message.subject.clone()))],
        }),
        ChannelKind::Teams | ChannelKind::Slack => Ok(Payload {
            content_type: JSON_TYPE,
            body: json!({ "text": text }).to_string(),
            headers: Vec::new(),
        }),
        ChannelKind::Sms => Ok(Payload {
            content_type: JSON_TYPE,
            body: json!({ "message": text }).to_string(),
            headers: Vec::new(),
        }),
    }
}


/// With a CA file only that CA is trusted; no redirect is followed and no proxy is read from the environment.
pub fn build_agent(settings: &TransportSettings) -> Result<Agent, TransportError> {
    let roots = match &settings.ca_file {
        Some(path) => {
            let pem = read_file_limited(Path::new(path)).map_err(|error| TransportError::CaFile(Box::new(error)))?;
            RootCerts::new_with_certs(&[Certificate::from_pem(pem.as_bytes()).map_err(TransportError::Certificate)?])
        }
        None => RootCerts::WebPki,
    };
    let config = Config::builder()
        .tls_config(TlsConfig::builder().root_certs(roots).build())
        .timeout_global(Some(Duration::from_millis(settings.timeout_millis)))
        .max_redirects(0)
        .https_only(true)
        .http_status_as_error(false)
        .proxy(None)
        .build();
    Ok(Agent::new_with_config(config))
}


/// The response body is never read: only the status counts, so a hostile receiver cannot feed anything back.
pub fn post(agent: &Agent, url: &Url, payload: &Payload) -> Result<(), TransportError> {
    let request = agent.post(url.as_str()).content_type(payload.content_type);
    let response = payload
        .headers
        .iter()
        .fold(request, |pending, (name, value)| pending.header(*name, value.as_str()))
        .send(payload.body.as_str())
        .map_err(TransportError::Request)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(TransportError::Status)
    }
}


/// One send with one settings snapshot; the secret, when the channel has one, becomes the bearer token and is zeroised on drop.
pub fn send_one(settings: &TransportSettings, channel: &Channel, message: &Message) -> Result<(), TransportError> {
    check_text(message)?;
    let url = https_url(channel)?;
    let mut prepared = payload(channel.kind, message)?;
    if let Some(file) = &channel.secret_file {
        let secret = read_secret(settings, &channel.tenant, file)?;
        prepared
            .headers
            .push(("Authorization", Zeroizing::new(format!("Bearer {}", secret.as_str()))));
    }
    post(&build_agent(settings)?, &url, &prepared)
}


/// The T109 sender: the error text is fixed (it never holds the target, a header or a secret) and `notify` reports `sender failed`.
pub fn https_sender(engine: &ReloadEngine<TransportSettings>) -> impl FnMut(&Channel, &Message) -> Result<(), String> + '_ {
    move |channel, message| send_one(&current_config(engine), channel, message).map_err(|error| error.to_string())
}
