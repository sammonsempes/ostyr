pub mod types;


use data_encoding::HEXLOWER;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};


pub const SEED_BYTE: u8 = 7;


pub const KEY_ID: &str = "acme-2026";


pub const PUBLISHER: &str = "acme";


pub const NOT_AFTER: u64 = 2_000;


pub const VALID_MANIFEST: &str = "name: example-sync
version: 1.2.3
publisher: acme
entry: main.py
runtime: python3
rights:
  - scope: devices:inventory
    access: read
actions:
  - name: restart-service
    targets: [devices:inventory]
    default_approval: human
config:
  - name: base-url
    kind: string
    required: true
  - name: token-file
    kind: secret_file
    required: true
";


pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[SEED_BYTE; SECRET_KEY_LENGTH])
}


pub fn public_hex() -> String {
    HEXLOWER.encode(&signing_key().verifying_key().to_bytes())
}


pub fn key_file_text(id: &str, publisher: &str, public: &str, not_after: u64) -> String {
    format!("keys:\n  - id: {id}\n    publisher: {publisher}\n    public_key: {public}\n    not_after: {not_after}\n")
}


pub fn manifest_with(replace_from: &str, replace_to: &str) -> String {
    VALID_MANIFEST.replacen(replace_from, replace_to, 1)
}
