use core_config::error::ConfigError;
use data_encoding::HEXLOWER;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use waf::error::WafError;
use waf::limits::{MAX_DIRECTORY_BYTES, MAX_HSTS_SECONDS};
use waf::model::{Budget, Issuer, RawIssuer, RawTls};
use waf::order::TOO_MANY_BYTES;
use waf::render::{render_text, render_text_capped};
use waf::tls::{
    check_ca_root, check_directory, check_email, check_hsts, check_pem, check_tls, ACME_FIELDS_MISSING, BAD_CA_ROOT_PATH, BAD_DIRECTORY, BAD_EMAIL,
    BAD_HSTS, INTERNAL_FIELDS, NOT_ONLY_CERTIFICATES, NOT_REGULAR_FILE, NO_CERTIFICATE,
};


const ACME_YAML: &str = "tests/fixtures/tls_acme.yaml";


const ACME_JSON: &str = "tests/fixtures/tls_acme.json";


const INTERNAL_YAML: &str = "tests/fixtures/tls_internal.yaml";


const INTERNAL_JSON: &str = "tests/fixtures/tls_internal.json";


const CA_PEM: &str = "tests/fixtures/ca.pem";


const PLAIN_YAML: &str = "tests/fixtures/two_routes.yaml";


const DIRECTORY: &str = "https://acme.example.test/directory";


const EMAIL: &str = "ops@example.test";


const OVER_HSTS: u64 = MAX_HSTS_SECONDS + 1;


const LOCAL_BYTES: usize = 64;


const OVER_LOCAL_BYTES: usize = 65;


const HALF: usize = 2;


const PROXIED_ROUTES: usize = 2;


const LABEL_BYTES: usize = 63;


const LAST_LABEL_BYTES: usize = 61;


const BIG_FILE_BYTES: usize = 65_537;


const SMALL_BUDGET_UPSTREAMS: usize = 2_000;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const BIG_BUDGET_BYTES: usize = 3_145_728;


fn raw(issuer: RawIssuer) -> RawTls {
    RawTls {
        issuer,
        directory: None,
        email: None,
        ca_root_file: None,
        hsts_max_age_seconds: None,
        hsts_include_subdomains: false,
    }
}


fn refused_reason(error: WafError) -> Option<&'static str> {
    match error {
        WafError::BadTls(reason) => Some(reason),
        _ => None,
    }
}


#[test]
fn both_goldens_match() -> Result<(), Box<dyn Error>> {
    [(ACME_YAML, ACME_JSON), (INTERNAL_YAML, INTERNAL_JSON)]
        .iter()
        .try_for_each(|(yaml, golden)| {
            let rendered = render_text(&fs::read_to_string(yaml)?)?;
            let expected: Value = serde_json::from_str(&fs::read_to_string(golden)?)?;
            assert_eq!(serde_json::to_value(&rendered.config)?, expected);
            assert!(rendered.refused.is_empty());
            Ok(())
        })
}


#[test]
fn no_output_ever_holds_on_demand() -> Result<(), Box<dyn Error>> {
    [ACME_YAML, INTERNAL_YAML, PLAIN_YAML].iter().try_for_each(|yaml| {
        let rendered = render_text(&fs::read_to_string(yaml)?)?;
        assert!(!serde_json::to_string(&rendered.config)?.contains("on_demand"));
        Ok(())
    })
}


#[test]
fn the_server_listens_on_443_with_a_tls_12_floor_and_redirects() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&fs::read_to_string(ACME_YAML)?)?;
    let value = serde_json::to_value(&rendered.config)?;
    assert_eq!(value.pointer("/apps/http/servers/main/listen"), Some(&json!([":443"])));
    assert_eq!(
        value.pointer("/apps/http/servers/main/tls_connection_policies"),
        Some(&json!([{"protocol_min": "tls1.2"}]))
    );
    assert_eq!(
        value.pointer("/apps/http/servers/main/automatic_https"),
        Some(&json!({"disable_redirects": false}))
    );
    Ok(())
}


#[test]
fn hsts_is_on_proxied_routes_only() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&fs::read_to_string(ACME_YAML)?)?;
    let value = serde_json::to_value(&rendered.config)?;
    let routes = value
        .pointer("/apps/http/servers/main/routes")
        .and_then(Value::as_array)
        .ok_or("no routes")?;
    let headers: Vec<Option<&Value>> = routes.iter().map(|route| route.pointer("/handle/0/headers/response/set")).collect();
    assert_eq!(headers.first(), Some(&None));
    assert_eq!(headers.last(), Some(&None));
    let proxied: Vec<&Option<&Value>> = headers.iter().skip(1).take(headers.len() - HALF).collect();
    assert_eq!(proxied.len(), PROXIED_ROUTES);
    assert!(proxied
        .iter()
        .all(|header| **header == Some(&json!({"Strict-Transport-Security": ["max-age=63072000; includeSubDomains"]}))));
    Ok(())
}


#[test]
fn a_max_age_of_zero_gives_no_header() -> Result<(), Box<dyn Error>> {
    let rendered = render_text(&fs::read_to_string(INTERNAL_YAML)?)?;
    assert!(!serde_json::to_string(&rendered.config)?.contains("Strict-Transport-Security"));
    Ok(())
}


#[test]
fn subjects_are_exactly_the_accepted_hosts() -> Result<(), Box<dyn Error>> {
    let text = json!({
        "tls": {"issuer": "internal"},
        "routes": [
            {"hosts": ["b.test"], "backends": ["127.0.0.1:9001"]},
            {"hosts": ["bad{.test"], "backends": ["127.0.0.1:9001"]},
            {"hosts": ["a.test", "B.test"], "paths": ["/x"], "backends": ["127.0.0.1:9001"]},
        ]
    })
    .to_string();
    let rendered = render_text(&text)?;
    let value = serde_json::to_value(&rendered.config)?;
    assert_eq!(rendered.refused.len(), 1);
    assert_eq!(
        value.pointer("/apps/tls/automation/policies/0/subjects"),
        Some(&json!(["a.test", "b.test"]))
    );
    assert_eq!(
        value.pointer("/apps/tls/automation/policies/0/issuers"),
        Some(&json!([{"module": "internal"}]))
    );
    Ok(())
}


#[test]
fn no_accepted_route_gives_no_policy() -> Result<(), Box<dyn Error>> {
    let text = json!({"tls": {"issuer": "internal"}, "routes": [{"hosts": ["bad{.test"], "backends": ["127.0.0.1:9001"]}]}).to_string();
    let value = serde_json::to_value(&render_text(&text)?.config)?;
    assert_eq!(value.pointer("/apps/tls/automation/policies"), Some(&json!([])));
    Ok(())
}


#[test]
fn the_acme_issuer_carries_the_directory_email_and_root_file_name() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("root.pem");
    fs::copy(CA_PEM, &path)?;
    let text = json!({
        "tls": {"issuer": "acme", "directory": DIRECTORY, "email": EMAIL, "ca_root_file": path.to_string_lossy()},
        "routes": [{"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]}]
    })
    .to_string();
    let rendered = render_text(&text)?;
    let name = rendered.ca_root.map(|root| root.name).ok_or("no root")?;
    let value = serde_json::to_value(&rendered.config)?;
    assert_eq!(
        value.pointer("/apps/tls/automation/policies/0/issuers"),
        Some(&json!([{"module": "acme", "ca": DIRECTORY, "email": EMAIL, "trusted_roots_pem_files": [name]}]))
    );
    Ok(())
}


#[test]
fn a_refused_tls_section_refuses_the_whole_file() -> Result<(), Box<dyn Error>> {
    let routes = json!([{"hosts": ["a.test"], "backends": ["127.0.0.1:9001"]}]);
    let bad = [
        json!({"issuer": "acme"}),
        json!({"issuer": "acme", "directory": "http://a.test/d", "email": EMAIL}),
        json!({"issuer": "internal", "email": EMAIL}),
        json!({"issuer": "internal", "hsts_max_age_seconds": OVER_HSTS}),
    ];
    bad.iter().try_for_each(|tls| {
        let result = render_text(&json!({"tls": tls, "routes": routes}).to_string());
        assert!(matches!(result, Err(WafError::BadTls(_))), "{tls}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let unknown = render_text(&json!({"tls": {"issuer": "internal", "on_demand": true}, "routes": routes}).to_string());
    assert!(matches!(unknown, Err(WafError::Config(_))));
    let wrong_issuer = render_text(&json!({"tls": {"issuer": "zerossl"}, "routes": routes}).to_string());
    assert!(matches!(wrong_issuer, Err(WafError::Config(_))));
    Ok(())
}


#[test]
fn route_bytes_account_for_tls() -> Result<(), Box<dyn Error>> {
    let text = fs::read_to_string(ACME_YAML)?;
    let size = serde_json::to_vec_pretty(&render_text(&text)?.config)?.len();
    let tight = render_text_capped(
        &text,
        &Budget {
            upstreams: SMALL_BUDGET_UPSTREAMS,
            bytes: size / HALF,
        },
    )?;
    assert!(tight.refused.iter().all(|refusal| refusal.reason == TOO_MANY_BYTES));
    assert!(!tight.refused.is_empty());
    let loose = render_text_capped(
        &text,
        &Budget {
            upstreams: SMALL_BUDGET_UPSTREAMS,
            bytes: BIG_BUDGET_BYTES,
        },
    )?;
    assert!(loose.refused.is_empty());
    Ok(())
}


#[test]
fn directory_grammar() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_directory(DIRECTORY), Ok(DIRECTORY.to_string()));
    assert_eq!(check_directory("https://acme.test"), Ok("https://acme.test".to_string()));
    assert_eq!(
        check_directory("https://10.0.0.1:14000/dir"),
        Ok("https://10.0.0.1:14000/dir".to_string())
    );
    let long = format!("https://a.test/{}", "a".repeat(MAX_DIRECTORY_BYTES - "https://a.test/".len()));
    assert!(check_directory(&long).is_ok());
    let too_long = format!("{long}a");
    let bad = [
        "http://acme.test/d",
        "HTTPS://acme.test/d",
        "https://user@acme.test/d",
        "https://user:pw@acme.test/d",
        "https://acme.test/%2e",
        "https://acme.test/d?x=1",
        "https://acme.test/\u{202e}d",
        "https://acme.test/d\"}",
        "https://acme.test/d\n",
        "https:///d",
        "https://acme.test:/d",
        "https://acme.test:0/d",
        "https://acme.test:70000/d",
        "https://acme.test:12a/d",
        "https://acme.test:123456/d",
        "https://acme.test:80:90/d",
        "https://-a.test/d",
        &too_long,
    ];
    bad.iter()
        .for_each(|directory| assert_eq!(check_directory(directory), Err(BAD_DIRECTORY), "{directory}"));
    Ok(())
}


#[test]
fn email_grammar() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_email("Ops.Team+x@Example.Test"), Ok("Ops.Team+x@example.test".to_string()));
    let local = "a".repeat(LOCAL_BYTES);
    assert!(check_email(&format!("{local}@example.test")).is_ok());
    let over_local = "a".repeat(OVER_LOCAL_BYTES);
    let at_limit_host = format!("{}.{}.{}", "b".repeat(LABEL_BYTES), "c".repeat(LABEL_BYTES), "d".repeat(LAST_LABEL_BYTES));
    assert!(check_email(&format!("{local}@{at_limit_host}")).is_ok());
    let too_long = format!("{local}@{at_limit_host}d");
    let bad = [
        "no-at-sign",
        "@example.test",
        "-ops@example.test",
        "o ps@example.test",
        "o\"ps@example.test",
        "ops@exa}mple.test",
        "ops@",
        "ops@a@b.test",
        "ops\u{202e}@example.test",
        &format!("{over_local}@example.test"),
        &too_long,
    ];
    bad.iter().for_each(|email| assert_eq!(check_email(email), Err(BAD_EMAIL), "{email}"));
    Ok(())
}


#[test]
fn hsts_values() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_hsts(Some(0), true), Ok(None));
    assert_eq!(check_hsts(Some(1), false), Ok(Some("max-age=1".to_string())));
    assert_eq!(
        check_hsts(Some(MAX_HSTS_SECONDS), true),
        Ok(Some("max-age=63072000; includeSubDomains".to_string()))
    );
    assert_eq!(check_hsts(None, false), Ok(Some("max-age=31536000".to_string())));
    assert_eq!(check_hsts(Some(OVER_HSTS), false), Err(BAD_HSTS));
    Ok(())
}


#[test]
fn pem_grammar() -> Result<(), Box<dyn Error>> {
    let canonical = fs::read_to_string(CA_PEM)?;
    assert_eq!(check_pem(&canonical), Ok(canonical.clone()));
    assert_eq!(check_pem(&format!("{canonical}{canonical}")), Ok(format!("{canonical}{canonical}")));
    assert_eq!(check_pem(""), Err(NO_CERTIFICATE));
    assert_eq!(check_pem("not a certificate"), Err(NO_CERTIFICATE));
    assert_eq!(
        check_pem("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
        Err(NO_CERTIFICATE)
    );
    Ok(())
}


#[test]
fn only_certificates_are_kept_and_any_other_section_refuses_the_file() -> Result<(), Box<dyn Error>> {
    let canonical = fs::read_to_string(CA_PEM)?;
    let key = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
    let unknown = "-----BEGIN SOMETHING-----\nAAAA\n-----END SOMETHING-----\n";
    assert_eq!(check_pem(&format!("{canonical}{key}")), Err(NOT_ONLY_CERTIFICATES));
    assert_eq!(check_pem(&format!("{key}{canonical}")), Err(NOT_ONLY_CERTIFICATES));
    assert_eq!(check_pem(&format!("{canonical}{unknown}")), Err(NOT_ONLY_CERTIFICATES));
    assert_eq!(check_pem(key), Err(NOT_ONLY_CERTIFICATES));
    let noisy = format!("db_password=hunter2\n{canonical}trailing text\n");
    assert_eq!(check_pem(&noisy), Ok(canonical));
    Ok(())
}


#[test]
fn the_kept_bytes_are_the_certificates_alone() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let canonical = fs::read_to_string(CA_PEM)?;
    let noisy = dir.path().join("noisy.pem");
    fs::write(&noisy, format!("db_password=hunter2\n{canonical}ignored\n"))?;
    let root = check_ca_root(&noisy.to_string_lossy())?;
    assert_eq!(root.pem, canonical);
    assert!(!root.pem.contains("hunter2"));
    assert_eq!(
        root.name,
        format!("ca-root-{}.pem", HEXLOWER.encode(&Sha256::digest(canonical.as_bytes())))
    );
    let bundle = dir.path().join("bundle.pem");
    fs::write(
        &bundle,
        format!("{canonical}-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"),
    )?;
    assert_eq!(
        check_ca_root(&bundle.to_string_lossy()).err().and_then(refused_reason),
        Some(NOT_ONLY_CERTIFICATES)
    );
    let directory = check_ca_root(&dir.path().to_string_lossy());
    assert_eq!(directory.err().and_then(refused_reason), Some(NOT_REGULAR_FILE));
    Ok(())
}


#[test]
fn the_ca_root_file_is_read_once_and_checked() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let good = dir.path().join("good.pem");
    fs::copy(CA_PEM, &good)?;
    let good_text = good.to_string_lossy().to_string();
    let root = check_ca_root(&good_text)?;
    assert_eq!(root.pem, fs::read_to_string(CA_PEM)?);
    assert_eq!(
        root.name,
        format!("ca-root-{}.pem", HEXLOWER.encode(&Sha256::digest(root.pem.as_bytes())))
    );
    let empty = dir.path().join("empty.pem");
    fs::write(&empty, "")?;
    let junk = dir.path().join("junk.pem");
    fs::write(&junk, "hello")?;
    let binary = dir.path().join("binary.pem");
    fs::write(&binary, INVALID_UTF8)?;
    let big = dir.path().join("big.pem");
    fs::write(&big, vec![b'a'; BIG_FILE_BYTES])?;
    let reasons: Vec<Option<&'static str>> = [&empty, &junk]
        .iter()
        .map(|path| check_ca_root(&path.to_string_lossy()).err().and_then(refused_reason))
        .collect();
    assert_eq!(reasons, [Some(NO_CERTIFICATE), Some(NO_CERTIFICATE)]);
    assert!(matches!(
        check_ca_root(&binary.to_string_lossy()),
        Err(WafError::Config(ConfigError::Io { .. }))
    ));
    assert!(matches!(
        check_ca_root(&big.to_string_lossy()),
        Err(WafError::Config(ConfigError::TooLarge { .. }))
    ));
    let missing = dir.path().join("missing.pem");
    assert!(matches!(check_ca_root(&missing.to_string_lossy()), Err(WafError::CaRoot(_))));
    ["relative.pem", "/etc/../x", "/a\"b"]
        .iter()
        .for_each(|path| assert_eq!(check_ca_root(path).err().and_then(refused_reason), Some(BAD_CA_ROOT_PATH), "{path}"));
    Ok(())
}


#[test]
fn issuer_field_combinations() -> Result<(), Box<dyn Error>> {
    let internal = check_tls(raw(RawIssuer::Internal))?;
    assert_eq!(internal.issuer, Issuer::Internal);
    let with_email = RawTls {
        email: Some(EMAIL.to_string()),
        ..raw(RawIssuer::Internal)
    };
    assert_eq!(check_tls(with_email).err().and_then(refused_reason), Some(INTERNAL_FIELDS));
    let with_directory = RawTls {
        directory: Some(DIRECTORY.to_string()),
        ..raw(RawIssuer::Internal)
    };
    assert_eq!(check_tls(with_directory).err().and_then(refused_reason), Some(INTERNAL_FIELDS));
    let with_root = RawTls {
        ca_root_file: Some(CA_PEM.to_string()),
        ..raw(RawIssuer::Internal)
    };
    assert_eq!(check_tls(with_root).err().and_then(refused_reason), Some(INTERNAL_FIELDS));
    let no_email = RawTls {
        directory: Some(DIRECTORY.to_string()),
        ..raw(RawIssuer::Acme)
    };
    assert_eq!(check_tls(no_email).err().and_then(refused_reason), Some(ACME_FIELDS_MISSING));
    let bad_email = RawTls {
        directory: Some(DIRECTORY.to_string()),
        email: Some("-x@example.test".to_string()),
        ..raw(RawIssuer::Acme)
    };
    assert_eq!(check_tls(bad_email).err().and_then(refused_reason), Some(BAD_EMAIL));
    let bad_directory = RawTls {
        directory: Some("http://a.test".to_string()),
        email: Some(EMAIL.to_string()),
        ..raw(RawIssuer::Acme)
    };
    assert_eq!(check_tls(bad_directory).err().and_then(refused_reason), Some(BAD_DIRECTORY));
    let missing_root = RawTls {
        directory: Some(DIRECTORY.to_string()),
        email: Some(EMAIL.to_string()),
        ca_root_file: Some("/nonexistent/root.pem".to_string()),
        ..raw(RawIssuer::Acme)
    };
    assert!(matches!(check_tls(missing_root), Err(WafError::CaRoot(_))));
    let good = RawTls {
        directory: Some(DIRECTORY.to_string()),
        email: Some(EMAIL.to_string()),
        ..raw(RawIssuer::Acme)
    };
    assert_eq!(
        check_tls(good)?.issuer,
        Issuer::Acme {
            directory: DIRECTORY.to_string(),
            email: EMAIL.to_string(),
            ca_root: None
        }
    );
    Ok(())
}


#[test]
fn a_malformed_marker_refuses_the_file_instead_of_being_dropped() -> Result<(), Box<dyn Error>> {
    let canonical = fs::read_to_string(CA_PEM)?;
    let bad_markers = [
        "-----BEGIN\tEC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        "----BEGIN EC PRIVATE KEY-----\nAAAA\n",
        "  -----BEGIN CERTIFICATE REQUEST-----\r\n",
        "-----END CERTIFICATE-----x\n",
    ];
    bad_markers.iter().try_for_each(|bad| -> Result<(), Box<dyn Error>> {
        assert_eq!(check_pem(&format!("{canonical}{bad}")), Err(NOT_ONLY_CERTIFICATES));
        assert_eq!(check_pem(bad), Err(NOT_ONLY_CERTIFICATES));
        Ok(())
    })
}


#[test]
fn caddy_never_installs_its_local_root_into_the_host_trust_store() -> Result<(), Box<dyn Error>> {
    [ACME_YAML, INTERNAL_YAML].iter().try_for_each(|path| -> Result<(), Box<dyn Error>> {
        let rendered = render_text(&fs::read_to_string(path)?)?;
        let value = serde_json::to_value(&rendered.config)?;
        assert_eq!(
            value.pointer("/apps/pki/certificate_authorities/local/install_trust"),
            Some(&json!(false))
        );
        Ok(())
    })?;
    let plain = serde_json::to_value(&render_text(&fs::read_to_string(PLAIN_YAML)?)?.config)?;
    assert!(plain.pointer("/apps/pki").is_none());
    Ok(())
}


#[test]
fn a_marker_in_the_middle_of_a_line_refuses_the_file() -> Result<(), Box<dyn Error>> {
    let canonical = fs::read_to_string(CA_PEM)?;
    assert_eq!(
        check_pem(&format!("{canonical}x -----BEGIN PRIVATE KEY-----\n")),
        Err(NOT_ONLY_CERTIFICATES)
    );
    Ok(())
}
