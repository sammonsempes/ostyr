#[path = "common/engine.rs"]
mod engine;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use core_config::reload::current_config;
use engine::{engine_for, feeds_text, replace_file};
use intel_feeds::config::{validate_feeds, validate_taxii, FeedConfig, FeedFormat, FeedsError, FeedsFile, OpenError, TaxiiConfig, TaxiiConfigError};
use intel_feeds::limits::{
    DEFAULT_TAXII_MAX_PAGES, DEFAULT_TAXII_PAGE_LIMIT, DEFAULT_TIMEOUT_MS, LIMIT_TAXII_MAX_PAGES, LIMIT_TAXII_PAGE_LIMIT, MAX_TAXII_COLLECTION_BYTES,
    MAX_TIMEOUT_MS, MAX_USER_BYTES,
};
use std::path::PathBuf;
use support::feed;
use tempfile::tempdir;
use types::TestResult;


const HUB: &str = "  - name: hub\n    format: taxii21\n    taxii:\n      api_root: https://taxii.example/api\n      collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116\n      user: reader\n      password_file: /etc/ostyr/taxii.password\n";


fn section() -> TaxiiConfig {
    TaxiiConfig {
        api_root: "https://taxii.example/api".to_owned(),
        collection: "abc-123".to_owned(),
        user: "reader".to_owned(),
        password_file: PathBuf::from("password"),
        ca_file: None,
        timeout_ms: DEFAULT_TIMEOUT_MS,
        max_pages: DEFAULT_TAXII_MAX_PAGES,
        page_limit: DEFAULT_TAXII_PAGE_LIMIT,
    }
}


fn taxii_feed(taxii: TaxiiConfig) -> FeedConfig {
    let mut config = feed("hub", FeedFormat::Taxii21);
    config.taxii = Some(taxii);
    config
}


fn file_with(feeds: Vec<FeedConfig>) -> FeedsFile {
    FeedsFile {
        feeds,
        ..FeedsFile::default()
    }
}


#[test]
fn a_taxii_feed_loads_with_its_defaults() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(HUB))?;
    let engine = engine_for(&path)?;
    let config = current_config(&engine);
    let hub = config.feeds.iter().find(|candidate| candidate.name == "hub").ok_or("no hub")?;
    let taxii = hub.taxii.as_ref().ok_or("no taxii section")?;
    assert_eq!(hub.format, FeedFormat::Taxii21);
    assert_eq!(
        (taxii.max_pages, taxii.page_limit, taxii.timeout_ms),
        (DEFAULT_TAXII_MAX_PAGES, DEFAULT_TAXII_PAGE_LIMIT, DEFAULT_TIMEOUT_MS)
    );
    assert!(taxii.ca_file.is_none() && hub.path.as_os_str().is_empty());
    Ok(())
}


#[test]
fn an_unknown_taxii_key_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(&format!("{HUB}      surprise: true\n")))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Config(_))));
    replace_file(&path, &feeds_text(&format!("{HUB}      max_pages: 101\n")))?;
    assert!(matches!(
        engine_for(&path),
        Err(OpenError::Invalid(FeedsError::Taxii(_, TaxiiConfigError::Pages)))
    ));
    Ok(())
}


#[test]
fn every_field_is_checked() -> TestResult {
    assert!(validate_taxii(&section()).is_ok());
    let long_collection = "a".repeat(MAX_TAXII_COLLECTION_BYTES + 1);
    let long_user = "u".repeat(MAX_USER_BYTES + 1);
    let collections = ["", "../x", "a/b", "a b", "a.b", "caf\u{e9}", "a?b=c", long_collection.as_str()];
    collections.iter().try_for_each(|name| -> TestResult {
        let taxii = TaxiiConfig {
            collection: (*name).to_owned(),
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::Collection)), "{name}");
        Ok(())
    })?;
    let users = ["", "a:b", "a b", "r\u{e9}", long_user.as_str()];
    users.iter().try_for_each(|name| -> TestResult {
        let taxii = TaxiiConfig {
            user: (*name).to_owned(),
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::User)), "{name}");
        Ok(())
    })?;
    let roots = [
        "http://taxii.example/api",
        "https://u:p@taxii.example/api",
        "https://taxii.example/api?x=1",
        "https://taxii.example/api#f",
        "ftp://x",
    ];
    roots.iter().try_for_each(|root| -> TestResult {
        let taxii = TaxiiConfig {
            api_root: (*root).to_owned(),
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::ApiRoot(_))), "{root}");
        Ok(())
    })?;
    let loopback = TaxiiConfig {
        api_root: "http://127.0.0.1:8080/taxii2/".to_owned(),
        ..section()
    };
    assert!(validate_taxii(&loopback).is_ok());
    [0, MAX_TIMEOUT_MS + 1].iter().try_for_each(|value| -> TestResult {
        let taxii = TaxiiConfig {
            timeout_ms: *value,
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::Timeout)));
        Ok(())
    })?;
    [0, LIMIT_TAXII_MAX_PAGES + 1].iter().try_for_each(|value| -> TestResult {
        let taxii = TaxiiConfig {
            max_pages: *value,
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::Pages)));
        Ok(())
    })?;
    [0, LIMIT_TAXII_PAGE_LIMIT + 1].iter().try_for_each(|value| -> TestResult {
        let taxii = TaxiiConfig {
            page_limit: *value,
            ..section()
        };
        assert!(matches!(validate_taxii(&taxii), Err(TaxiiConfigError::PageLimit)));
        Ok(())
    })?;
    let edge = TaxiiConfig {
        max_pages: LIMIT_TAXII_MAX_PAGES,
        page_limit: LIMIT_TAXII_PAGE_LIMIT,
        timeout_ms: MAX_TIMEOUT_MS,
        ..section()
    };
    assert!(validate_taxii(&edge).is_ok());
    Ok(())
}


#[test]
fn the_section_belongs_to_taxii_feeds_only() -> TestResult {
    let bare = file_with(vec![feed("hub", FeedFormat::Taxii21)]);
    assert!(matches!(validate_feeds(&bare), Err(FeedsError::Taxii(_, TaxiiConfigError::Section))));
    let mut stray = feed("list", FeedFormat::Crowdsec);
    stray.taxii = Some(section());
    assert!(matches!(
        validate_feeds(&file_with(vec![stray])),
        Err(FeedsError::Taxii(_, TaxiiConfigError::Section))
    ));
    assert!(validate_feeds(&file_with(vec![taxii_feed(section()), feed("list", FeedFormat::Crowdsec)])).is_ok());
    let refused = validate_feeds(&file_with(vec![taxii_feed(TaxiiConfig {
        user: String::new(),
        ..section()
    })]));
    assert!(matches!(refused, Err(FeedsError::Taxii(name, TaxiiConfigError::User)) if name == "hub"));
    Ok(())
}
