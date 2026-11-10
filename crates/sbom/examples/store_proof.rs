//! Live proof against an S3-compatible store: `store_proof <endpoint> <ca.pem> <access-key-file> <secret-key-file> <bucket> <region>` (Garage lab region: `garage`).

use ed25519_dalek::SigningKey;
use sbom::model::{DocumentMeta, Limits, SignedDocument, StoreMethod, StoreScope, TrustedKey};
use sbom::signing::{memory_signer, sign_document};
use sbom::store::{exchange, object_keys, put_version, read_version};
use sbom::store_settings::StoreSettings;
use sbom::transport::open_https_store;
use sbom::types::TrustedKeys;
use std::io::Write;
use std::path::PathBuf;


const SEED: [u8; 32] = [42; 32];


const KEY_ID: &str = "example";


const NOW: u64 = 1;


const TIMEOUT_MILLIS: u64 = 10_000;


const FIRST: &str = r#"{"components":[{"type":"library","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#;


const SECOND: &str = r#"{"components":[{"type":"library","name":"a","version":"2","purl":"pkg:cargo/a@2"}]}"#;


const SECOND_VERSION: u64 = 2;


const ARGUMENTS: usize = 7;


fn meta(tenant: &str, version: u64) -> DocumentMeta {
    DocumentMeta {
        tenant: tenant.to_owned(),
        artefact: "debian-12".to_owned(),
        version,
    }
}


fn scope(tenant: &str) -> StoreScope {
    StoreScope { tenant: tenant.to_owned() }
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let [_program, endpoint, ca_file, access_key_file, secret_key_file, bucket, region] =
        <[String; ARGUMENTS]>::try_from(arguments).map_err(|rejected| {
            format!(
                "usage: store_proof <endpoint> <ca.pem> <access-key-file> <secret-key-file> <bucket> <region>, got {} arguments",
                rejected.len()
            )
        })?;
    let store = open_https_store(&StoreSettings {
        endpoint,
        bucket,
        region,
        ca_file: Some(PathBuf::from(ca_file)),
        access_key_file: PathBuf::from(access_key_file),
        secret_key_file: PathBuf::from(secret_key_file),
        connect_millis: TIMEOUT_MILLIS,
        read_millis: TIMEOUT_MILLIS,
        total_millis: TIMEOUT_MILLIS,
    })?;
    let key = SigningKey::from_bytes(&SEED);
    let keys = TrustedKeys::from([(
        KEY_ID.to_owned(),
        TrustedKey {
            public_key: key.verifying_key(),
            not_before: 0,
            not_after: u64::MAX,
            revoked: false,
        },
    )]);
    let signer = memory_signer(key);
    let limits = Limits::default();
    let mut out = std::io::stdout();
    for (tenant, version, text) in [("tenant-a", 1, FIRST), ("tenant-a", SECOND_VERSION, SECOND), ("tenant-b", 1, SECOND)] {
        let document_meta = meta(tenant, version);
        let signature = sign_document(text.as_bytes(), &document_meta, KEY_ID, &*signer, &limits)?;
        let document = SignedDocument {
            bytes: text.as_bytes().to_vec(),
            meta: document_meta,
            signature,
        };
        writeln!(
            out,
            "put {tenant}/{version}: {:?}",
            put_version(&store, &scope(tenant), &document, &limits)
        )?;
    }
    for (tenant, version) in [("tenant-a", 1), ("tenant-a", SECOND_VERSION), ("tenant-b", 1)] {
        let read = read_version(&store, &scope(tenant), &meta(tenant, version), &keys, NOW, &limits);
        writeln!(
            out,
            "read {tenant}/{version}: {:?}",
            read.map(|document| String::from_utf8_lossy(&document.bytes).into_owned())
        )?;
    }
    let crossing = read_version(&store, &scope("tenant-b"), &meta("tenant-a", 1), &keys, NOW, &limits);
    writeln!(out, "tenant-b reads tenant-a/1: {:?}", crossing.map(|_document| "READ"))?;
    let keys_of_a = object_keys(&meta("tenant-a", 1))?;
    exchange(&store, StoreMethod::Put, &keys_of_a.document, SECOND.as_bytes().to_vec(), 0)?;
    let tampered = read_version(&store, &scope("tenant-a"), &meta("tenant-a", 1), &keys, NOW, &limits);
    writeln!(out, "tampered tenant-a/1: {:?}", tampered.map(|_document| "READ"))?;
    Ok(())
}
