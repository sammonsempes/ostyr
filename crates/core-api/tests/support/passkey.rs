use crate::fixture::{config_in, extra_access, extra_router, private_file, Fixture, PASSWORD, READER};
use crate::types::TestError;
use core_api::example::example_document;
use core_api::routes::build_router;
use core_api::state::build_state;
use core_api::types::SharedState;
use core_auth::cli::read_key_file;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use std::sync::Arc;
use tempfile::tempdir;


pub const CREATED_AT: i64 = 1_700_000_012;


pub const STORE_VERSION: u32 = 2;


pub fn stored_passkey() -> serde_json::Value {
    serde_json::json!({
        "username": READER,
        "id": "jgUEVIVzNqfEPqeU9eUwhERykDk05jE43P57f36vpz0",
        "name": "laptop",
        "created_at": CREATED_AT,
        "last_used": null,
        "passkey": {
            "cred": {
                "attestation": { "data": "Self_", "metadata": "None" },
                "attestation_format": "packed",
                "backup_eligible": false,
                "backup_state": false,
                "counter": 0,
                "cred": {
                    "key": { "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": "8Q9nFeXiVoP2--eeaKJQcwq5qgjWb0ikvofvEifIZsY",
                        "y": "ulguZw7WvpvveCmpdHW82c5s35UEkkMCzI4gZDnyV4g"
                    } },
                    "type_": "ES256"
                },
                "cred_id": "jgUEVIVzNqfEPqeU9eUwhERykDk05jE43P57f36vpz0",
                "extensions": {
                    "appid": "NotRequested",
                    "cred_props": "Ignored",
                    "cred_protect": "Ignored",
                    "hmac_create_secret": "NotRequested"
                },
                "registration_policy": "required",
                "transports": null,
                "user_verified": true
            }
        }
    })
}


pub fn fixture_with_passkey() -> Result<Fixture, TestError> {
    let dir = tempdir()?;
    let config = config_in(&dir)?;
    let store = serde_json::json!({
        "version": STORE_VERSION,
        "accounts": [{
            "username": READER,
            "password_hash": hash_password(PASSWORD, os_random)?,
            "roles": ["reader"],
            "totp": null
        }],
        "credentials": [stored_passkey()]
    });
    private_file(&config.accounts_store, store.to_string().as_bytes())?;
    let built = build_state(
        &config,
        Arc::new(read_key_file(&config.key_file)?),
        extra_access(),
        vec![example_document()],
    )?;
    let state: SharedState = Arc::new(built);
    let router = build_router(state.clone(), extra_router());
    Ok(Fixture { dir, state, router, config })
}
