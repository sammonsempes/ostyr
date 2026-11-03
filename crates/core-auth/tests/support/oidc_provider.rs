use data_encoding::{BASE64, BASE64URL_NOPAD};
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::http::{header, Response};
use openidconnect::url::form_urlencoded;
use openidconnect::{HttpRequest, HttpResponse, JsonWebKeyId, JsonWebKeySet, PrivateSigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::io;


pub const ISSUER: &str = "https://idp.example";


pub const CLIENT_ID: &str = "test-client";


pub const CLIENT_SECRET: &str = "test-secret";


pub const KEY_ID: &str = "key-1";


pub const GOOD_KEY: &str = include_str!("../fixtures/good_key.pem");


pub const OTHER_KEY: &str = include_str!("../fixtures/other_key.pem");


pub const SCHEME_HTTPS: &str = "https";


pub const SCHEME_HTTP: &str = "http";


pub const STATUS_OK: u16 = 200;


pub const STATUS_BAD_REQUEST: u16 = 400;


pub const STATUS_ERROR: u16 = 500;


pub struct Provider {
    pub id_token: Option<String>,
    pub token_status: u16,
    pub challenge: Option<String>,
    pub with_token_endpoint: bool,
    pub token_scheme: &'static str,
    pub jwks_scheme: &'static str,
    pub discoveries_left: Cell<usize>,
}


pub fn provider(id_token: Option<String>, challenge: Option<String>) -> Provider {
    Provider {
        id_token,
        token_status: STATUS_OK,
        challenge,
        with_token_endpoint: true,
        token_scheme: SCHEME_HTTPS,
        jwks_scheme: SCHEME_HTTPS,
        discoveries_left: Cell::new(usize::MAX),
    }
}


pub fn reply(status: u16, body: &Value) -> Result<HttpResponse, io::Error> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into_bytes())
        .map_err(io::Error::other)
}


pub fn signing_key(pem: &str) -> Result<CoreRsaPrivateSigningKey, Box<dyn std::error::Error>> {
    Ok(CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(KEY_ID.to_owned())))?)
}


pub fn make_jwt(pem: &str, claims: &Value) -> Result<String, Box<dyn std::error::Error>> {
    let header_part = BASE64URL_NOPAD.encode(json!({"alg": "RS256", "typ": "JWT", "kid": KEY_ID}).to_string().as_bytes());
    let payload_part = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
    let message = format!("{header_part}.{payload_part}");
    let signature = signing_key(pem)?.sign(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, message.as_bytes())?;
    Ok(format!("{message}.{}", BASE64URL_NOPAD.encode(&signature)))
}


pub fn jwks() -> Result<Value, Box<dyn std::error::Error>> {
    let key: CoreJsonWebKey = signing_key(GOOD_KEY)?.as_verification_key();
    Ok(serde_json::to_value(JsonWebKeySet::new(vec![key]))?)
}


pub fn metadata(with_token_endpoint: bool) -> Value {
    metadata_with(with_token_endpoint, SCHEME_HTTPS, SCHEME_HTTPS)
}


pub fn metadata_with(with_token_endpoint: bool, token_scheme: &str, jwks_scheme: &str) -> Value {
    let host = ISSUER.trim_start_matches("https://");
    let mut document = json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "jwks_uri": format!("{jwks_scheme}://{host}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });
    if with_token_endpoint {
        if let Some(map) = document.as_object_mut() {
            map.insert("token_endpoint".to_owned(), json!(format!("{token_scheme}://{host}/token")));
        }
    }
    document
}


pub fn challenge_of(verifier: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
}


pub fn token_request_valid(provider: &Provider, request: &HttpRequest) -> bool {
    let expected_header = format!("Basic {}", BASE64.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}").as_bytes()));
    let authorised = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected_header);
    let verifier = form_urlencoded::parse(request.body())
        .find(|(name, _)| name == "code_verifier")
        .map(|(_, value)| value.into_owned());
    let pkce_ok = provider
        .challenge
        .as_ref()
        .is_none_or(|challenge| verifier.is_some_and(|value| &challenge_of(&value) == challenge));
    authorised && pkce_ok
}


pub fn respond(provider: &Provider, request: HttpRequest) -> Result<HttpResponse, io::Error> {
    match request.uri().path() {
        "/.well-known/openid-configuration" => match provider.discoveries_left.get().checked_sub(1) {
            Some(left) => {
                provider.discoveries_left.set(left);
                reply(
                    STATUS_OK,
                    &metadata_with(provider.with_token_endpoint, provider.token_scheme, provider.jwks_scheme),
                )
            }
            None => reply(STATUS_ERROR, &json!({})),
        },
        "/jwks" => reply(STATUS_OK, &jwks().map_err(|error| io::Error::other(error.to_string()))?),
        "/token" if !token_request_valid(provider, &request) => reply(STATUS_BAD_REQUEST, &json!({"error": "invalid_grant"})),
        "/token" if provider.token_status != STATUS_OK => reply(provider.token_status, &json!({"error": "server_error"})),
        "/token" => {
            let mut body = json!({"access_token": "access", "token_type": "bearer"});
            if let Some(token) = &provider.id_token {
                if let Some(map) = body.as_object_mut() {
                    map.insert("id_token".to_owned(), json!(token));
                }
            }
            reply(STATUS_OK, &body)
        }
        _ => reply(STATUS_ERROR, &json!({})),
    }
}
