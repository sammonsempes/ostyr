//! Signs a CycloneDX file, verifies it, then verifies a tampered copy: `sign_sbom <file>`.

use ed25519_dalek::SigningKey;
use sbom::model::{DocumentMeta, Limits, TrustedKey};
use sbom::signing::{memory_signer, sign_document, verify_document};
use sbom::types::TrustedKeys;
use std::io::Write;


const SEED: [u8; 32] = [42; 32];


const KEY_ID: &str = "example";


const NOW: u64 = 1;


const VALID_UNTIL: u64 = 10;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: sign_sbom <file>")?;
    let bytes = std::fs::read(path)?;
    let key = SigningKey::from_bytes(&SEED);
    let keys = TrustedKeys::from([(
        KEY_ID.to_owned(),
        TrustedKey {
            public_key: key.verifying_key(),
            not_before: 0,
            not_after: VALID_UNTIL,
            revoked: false,
        },
    )]);
    let meta = DocumentMeta {
        tenant: "tenant-a".to_owned(),
        artefact: "debian-12".to_owned(),
        version: 1,
    };
    let limits = Limits::default();
    let signature = sign_document(&bytes, &meta, KEY_ID, &*memory_signer(key), &limits)?;
    let mut out = std::io::stdout();
    writeln!(out, "genuine: {:?}", verify_document(&bytes, &meta, &signature, &keys, NOW, &limits))?;
    let mut tampered = bytes;
    tampered.push(b' ');
    writeln!(out, "tampered: {:?}", verify_document(&tampered, &meta, &signature, &keys, NOW, &limits))?;
    Ok(())
}
