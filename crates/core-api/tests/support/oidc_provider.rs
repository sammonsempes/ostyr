use super::oidc_types::TokenCell;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::http::{header, Response};
use openidconnect::{HttpRequest, HttpResponse, JsonWebKeyId, JsonWebKeySet, PrivateSigningKey};
use serde_json::{json, Value};
use std::io;


pub const ISSUER: &str = "https://idp.example";


pub const CLIENT_ID: &str = "test-client";


pub const CLIENT_SECRET: &str = "test-secret";


pub const KEY_ID: &str = "key-1";


pub const GOOD_KEY: &str = include_str!("../fixtures/good_key.pem");


pub const STATUS_OK: u16 = 200;


pub const STATUS_BAD_REQUEST: u16 = 400;


pub const STATUS_ERROR: u16 = 500;


pub fn reply(status: u16, body: &Value) -> Result<HttpResponse, io::Error> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string().into_bytes())
        .map_err(io::Error::other)
}


pub fn signing_key() -> Result<CoreRsaPrivateSigningKey, Box<dyn std::error::Error>> {
    Ok(CoreRsaPrivateSigningKey::from_pem(GOOD_KEY, Some(JsonWebKeyId::new(KEY_ID.to_owned())))?)
}


pub fn make_jwt(claims: &Value) -> Result<String, Box<dyn std::error::Error>> {
    let header_part = BASE64URL_NOPAD.encode(json!({"alg": "RS256", "typ": "JWT", "kid": KEY_ID}).to_string().as_bytes());
    let payload_part = BASE64URL_NOPAD.encode(claims.to_string().as_bytes());
    let message = format!("{header_part}.{payload_part}");
    let signature = signing_key()?.sign(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256, message.as_bytes())?;
    Ok(format!("{message}.{}", BASE64URL_NOPAD.encode(&signature)))
}


pub fn jwks() -> Result<Value, Box<dyn std::error::Error>> {
    let key: CoreJsonWebKey = signing_key()?.as_verification_key();
    Ok(serde_json::to_value(JsonWebKeySet::new(vec![key]))?)
}


pub fn metadata() -> Value {
    json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "token_endpoint": format!("{ISSUER}/token"),
        "jwks_uri": format!("{ISSUER}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })
}


pub fn token_authorised(request: &HttpRequest) -> bool {
    let expected = format!("Basic {}", BASE64.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}").as_bytes()));
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected)
}


pub fn respond(token: &TokenCell, request: HttpRequest) -> Result<HttpResponse, io::Error> {
    match request.uri().path() {
        "/.well-known/openid-configuration" => reply(STATUS_OK, &metadata()),
        "/jwks" => reply(STATUS_OK, &jwks().map_err(|error| io::Error::other(error.to_string()))?),
        "/token" if !token_authorised(&request) => reply(STATUS_BAD_REQUEST, &json!({"error": "invalid_grant"})),
        "/token" => {
            let id_token = token.lock().map_err(|_| io::Error::other("poisoned"))?.clone();
            reply(
                STATUS_OK,
                &json!({"access_token": "access", "token_type": "bearer", "id_token": id_token}),
            )
        }
        _ => reply(STATUS_ERROR, &json!({})),
    }
}
