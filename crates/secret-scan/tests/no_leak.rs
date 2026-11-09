#[path = "common/types.rs"]
mod types;


use data_encoding::HEXLOWER;
use secret_scan::model::{Limits, ScanScope};
use secret_scan::report::parse_report;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::TestResult;


struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().map_err(|_| std::io::Error::other("poisoned"))?.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


const TINY_BYTES: usize = 40;


const SAMPLE: &[u8] = include_bytes!("fixtures/gitleaks-report.json");


const SECRETS: [&str; 3] = [
    "AKIAIOSFODNN7EXAMPLE",
    "s3cr3tValue-9f8e7d6c5b4a",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
];


const MALFORMED: &[u8] = br#"[{"File":"a","StartLine":"x","EndLine":1,"RuleID":"r","Match":"k=MALFORMEDSECRET99","Secret":"MALFORMEDSECRET99"}]"#;


fn needles() -> Vec<String> {
    SECRETS
        .iter()
        .chain(["MALFORMEDSECRET99"].iter())
        .flat_map(|secret| {
            let digest = Sha256::digest(secret.as_bytes());
            [(*secret).to_string(), HEXLOWER.encode(&digest), HEXLOWER.encode(&digest).to_uppercase()]
        })
        .collect()
}


fn assert_clean(haystack: &str) {
    needles()
        .iter()
        .for_each(|needle| assert!(!haystack.contains(needle.as_str()), "found {needle}"));
}


#[test]
fn no_output_holds_the_secret_or_its_hash() -> TestResult {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BoxMakeWriter::new(move || SharedBuffer(Arc::clone(&sink))))
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let outputs = tracing::subscriber::with_default(subscriber, || -> TestResult {
        let scope = ScanScope::default();
        let report = parse_report(SAMPLE, &Limits::default(), "acme", "s", &scope)?;
        let malformed = parse_report(MALFORMED, &Limits::default(), "acme", "s", &scope)?;
        assert_eq!(malformed.malformed, 1);
        let tiny = Limits {
            max_bytes: TINY_BYTES,
            ..Limits::default()
        };
        let too_large = parse_report(SAMPLE, &tiny, "acme", "s", &scope).err().ok_or("expected error")?;
        let few = Limits {
            max_findings: 1,
            ..Limits::default()
        };
        let too_many = parse_report(SAMPLE, &few, "acme", "s", &scope).err().ok_or("expected error")?;
        let json = serde_json::to_string(&report)?;
        let rendered = [
            format!("{report:?}"),
            format!("{malformed:?}"),
            json,
            format!("{too_large} {too_large:?}"),
            format!("{too_many} {too_many:?}"),
        ];
        rendered.iter().for_each(|text| assert_clean(text));
        Ok(())
    });
    outputs?;
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("malformed gitleaks finding skipped"));
    assert_clean(&log);
    Ok(())
}
