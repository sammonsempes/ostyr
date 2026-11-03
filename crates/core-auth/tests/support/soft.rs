#[path = "webauthn/types.rs"]
mod soft_types;


use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
pub use soft_types::SoftResult;
use webauthn_authenticator_rs::prelude::{Url, WebauthnAuthenticator};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};


pub fn soft_passkey() -> SoftPasskey {
    SoftPasskey::new(true)
}


pub fn origin(text: &str) -> SoftResult<Url> {
    Ok(Url::parse(text)?)
}


pub fn register_with(soft: &mut SoftPasskey, origin: &Url, options: CreationChallengeResponse) -> SoftResult<RegisterPublicKeyCredential> {
    Ok(soft.do_registration(origin.clone(), options)?)
}


pub fn assert_with(soft: &mut SoftPasskey, origin: &Url, options: RequestChallengeResponse) -> SoftResult<PublicKeyCredential> {
    Ok(soft.do_authentication(origin.clone(), options)?)
}


pub fn set_at(value: &mut Value, pointer: &str, replacement: Value) -> SoftResult<()> {
    *value.pointer_mut(pointer).ok_or("missing JSON member")? = replacement;
    Ok(())
}


pub fn edited<Document: Serialize + DeserializeOwned>(document: &Document, pointer: &str, replacement: Value) -> SoftResult<Document> {
    let mut value = serde_json::to_value(document)?;
    set_at(&mut value, pointer, replacement)?;
    Ok(serde_json::from_value(value)?)
}


/// What a browser does for a discoverable credential: the software token needs the credential listed, the user handle is attached afterwards.
pub fn discoverable_assertion(
    soft: &mut SoftPasskey,
    origin: &Url,
    options: RequestChallengeResponse,
    (credential_id, user_handle): (&str, Option<&str>),
) -> SoftResult<PublicKeyCredential> {
    let listed = edited(
        &options,
        "/publicKey/allowCredentials",
        json!([{ "type": "public-key", "id": credential_id }]),
    )?;
    let response = assert_with(soft, origin, listed)?;
    edited(&response, "/response/userHandle", user_handle.map_or(Value::Null, |handle| json!(handle)))
}
