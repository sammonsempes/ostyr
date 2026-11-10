use ed25519_dalek::SigningKey;
use rusty_s3::{Bucket, Credentials, UrlStyle};
use sbom::model::{DocumentMeta, HttpResponse, Limits, SignedDocument, Store, StoreMethod, StoreScope, TrustedKey};
use sbom::signing::{memory_signer, sign_document};
use sbom::types::{BoxError, HttpFn, TrustedKeys};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;


pub const KEY_ID: &str = "sbom-1";


pub const SEED_LENGTH: usize = 32;


pub const SEED: [u8; SEED_LENGTH] = [7; SEED_LENGTH];


pub const STATUS_OK: u16 = 200;


pub const STATUS_NOT_FOUND: u16 = 404;


pub const EXPIRY_SECONDS: u64 = 60;


pub const SECRET_KEY: &str = "very-secret-key-material";


pub const NOW: u64 = 1_000;


pub const FIRST: &str = r#"{"components":[{"type":"library","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#;


pub const SECOND: &str = r#"{"components":[{"type":"library","name":"a","version":"2","purl":"pkg:cargo/a@2"}]}"#;


pub fn meta(tenant: &str, version: u64) -> DocumentMeta {
    DocumentMeta {
        tenant: tenant.to_owned(),
        artefact: "image-x".to_owned(),
        version,
    }
}


pub fn scope(tenant: &str) -> StoreScope {
    StoreScope { tenant: tenant.to_owned() }
}


pub fn store_with(http: Box<HttpFn>) -> Result<Store, Box<dyn std::error::Error>> {
    Ok(Store {
        bucket: Bucket::new("https://minio.example:9000".parse()?, UrlStyle::Path, "sboms", "us-east-1")?,
        credentials: Credentials::new("AKIDEXAMPLE", SECRET_KEY),
        expiry: Duration::from_secs(EXPIRY_SECONDS),
        http,
    })
}


pub fn answering(status: u16, body: Vec<u8>) -> Box<HttpFn> {
    Box::new(move |_request| Ok(HttpResponse { status, body: body.clone() }))
}


pub fn failing() -> Box<HttpFn> {
    Box::new(|_request| Err(BoxError::from("connection refused")))
}


pub fn memory_http(objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>, calls: Arc<AtomicUsize>) -> Box<HttpFn> {
    Box::new(move |request| -> Result<HttpResponse, BoxError> {
        calls.fetch_add(1, Ordering::SeqCst);
        let path = Url::parse(&request.url)?.path().to_owned();
        let mut map = objects.lock().map_err(|_poisoned| "poisoned")?;
        match request.method {
            StoreMethod::Put => {
                map.insert(path, request.body.clone());
                Ok(HttpResponse {
                    status: STATUS_OK,
                    body: Vec::new(),
                })
            }
            StoreMethod::Get => Ok(match map.get(&path) {
                Some(found) => HttpResponse {
                    status: STATUS_OK,
                    body: found.iter().take(request.max_response).copied().collect(),
                },
                None => HttpResponse {
                    status: STATUS_NOT_FOUND,
                    body: Vec::new(),
                },
            }),
        }
    })
}


pub struct Fixture {
    pub store: Store,
    pub objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    pub calls: Arc<AtomicUsize>,
}


pub fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let objects = Arc::new(Mutex::new(BTreeMap::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    Ok(Fixture {
        store: store_with(memory_http(objects.clone(), calls.clone()))?,
        objects,
        calls,
    })
}


pub fn signed(tenant: &str, version: u64, text: &str) -> Result<SignedDocument, Box<dyn std::error::Error>> {
    let meta_value = meta(tenant, version);
    let signer = memory_signer(SigningKey::from_bytes(&SEED));
    let signature = sign_document(text.as_bytes(), &meta_value, KEY_ID, &*signer, &Limits::default())?;
    Ok(SignedDocument {
        bytes: text.as_bytes().to_vec(),
        meta: meta_value,
        signature,
    })
}


pub fn trusted() -> TrustedKeys {
    std::iter::once((
        KEY_ID.to_owned(),
        TrustedKey {
            public_key: SigningKey::from_bytes(&SEED).verifying_key(),
            not_before: 0,
            not_after: u64::MAX,
            revoked: false,
        },
    ))
    .collect()
}
