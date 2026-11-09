#[path = "common/types.rs"]
mod types;


use status_page::config::{load_config, validate_config};
use status_page::error::StatusPageError;
use status_page::model::{Limits, PageConfig, DEFAULT_LIMITS};
use std::fs;
use types::TestResult;


const SAMPLE: &str = "id: main
tenant: acme
title: Acme status
components:
  - name: Website
    service: svc-web
    objective_ppm: 999000
  - name: API
    service: svc-api
  - name: Mail
    service: svc-mail
";


const TINY: usize = 3;


const OBJECTIVE: u32 = 999_000;


fn load_text(text: &str, limits: &Limits) -> std::io::Result<Result<PageConfig, StatusPageError>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("page.yaml");
    fs::write(&path, text)?;
    Ok(load_config(&path, limits))
}


#[test]
fn sample_loads_in_order() -> TestResult {
    let config = load_text(SAMPLE, &DEFAULT_LIMITS)??;
    let names: Vec<&str> = config.components.iter().map(|component| component.name.as_str()).collect();
    assert_eq!(names, ["Website", "API", "Mail"]);
    assert_eq!(config.components.first().ok_or("first")?.objective_ppm, Some(OBJECTIVE));
    Ok(())
}


#[test]
fn unknown_key_and_missing_file_are_refused() -> TestResult {
    let unknown = load_text(&format!("{SAMPLE}extra: 1\n"), &DEFAULT_LIMITS)?;
    assert!(matches!(unknown, Err(StatusPageError::Config(_))));
    let dir = tempfile::tempdir()?;
    let missing = load_config(&dir.path().join("absent.yaml"), &DEFAULT_LIMITS);
    assert!(matches!(missing, Err(StatusPageError::Config(_))));
    Ok(())
}


#[test]
fn bounds_and_duplicates_are_refused() -> TestResult {
    let text_limit = Limits {
        max_text_bytes: TINY,
        ..DEFAULT_LIMITS
    };
    let count_limit = Limits {
        max_components: 1,
        ..DEFAULT_LIMITS
    };
    let long_title = load_text(SAMPLE, &text_limit)?;
    assert!(matches!(long_title, Err(StatusPageError::TextTooLong { .. })));
    let short_header = "id: a\ntenant: b\ntitle: c\ncomponents:\n";
    let long_name = load_text(&format!("{short_header}  - name: Website\n    service: s\n"), &text_limit)?;
    assert!(matches!(long_name, Err(StatusPageError::TextTooLong { field: "component name", .. })));
    let long_service = load_text(&format!("{short_header}  - name: n\n    service: svc-long\n"), &text_limit)?;
    assert!(matches!(long_service, Err(StatusPageError::TextTooLong { field: "service", .. })));
    assert!(matches!(load_text(SAMPLE, &count_limit)?, Err(StatusPageError::TooMany { .. })));
    let duplicate = load_text(
        &format!("{short_header}  - name: n\n    service: s\n  - name: m\n    service: s\n"),
        &DEFAULT_LIMITS,
    )?;
    assert!(matches!(duplicate, Err(StatusPageError::DuplicateService)));
    let config = load_text(SAMPLE, &DEFAULT_LIMITS)??;
    let id_limit = Limits {
        max_text_bytes: 0,
        ..DEFAULT_LIMITS
    };
    assert!(matches!(
        validate_config(&config, &id_limit),
        Err(StatusPageError::TextTooLong { field: "id", .. })
    ));
    let mut short_id = config.clone();
    short_id.id = "x".to_string();
    assert!(matches!(
        validate_config(
            &short_id,
            &Limits {
                max_text_bytes: 1,
                ..DEFAULT_LIMITS
            }
        ),
        Err(StatusPageError::TextTooLong { field: "tenant", .. })
    ));
    Ok(())
}
