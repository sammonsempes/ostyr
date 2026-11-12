#[path = "common/types.rs"]
mod types;


use status_page::error::StatusPageError;
use status_page::html::{figure_text, percent_text, state_label};
use status_page::model::{
    ComponentConfig, ComponentState, FigureInput, IncidentInput, IncidentUpdateInput, Limits, Omitted, PageConfig, PublicFigure, ServiceState,
    DEFAULT_LIMITS,
};
use status_page::render::{render, render_omitting, worst_state};
use types::TestResult;


const TENANT: &str = "acme";


const NOW: i64 = 1_700_000_000;


const SECRET_NOTE: &str = "internal 10.0.0.5 note";


const ASSET: &str = "asset-77f3";


const SMALL: usize = 10;


const TEXT_LIMIT: usize = 20;


const MID_PPM: u32 = 999_000;


const HIGH_PPM: u32 = 999_900;


const LOW_PPM: u32 = 990_000;


const ALL_STATES: usize = 6;


const THREE: usize = 3;


const LATER: i64 = 2;


const NEWEST: i64 = 5;


const DROPPED_STATES: usize = 2;


fn component(name: &str, service: &str, objective_ppm: Option<u32>) -> ComponentConfig {
    ComponentConfig {
        name: name.to_string(),
        service: service.to_string(),
        objective_ppm,
        rule: None,
    }
}


fn config() -> PageConfig {
    PageConfig {
        id: "main".to_string(),
        tenant: TENANT.to_string(),
        title: "Acme status".to_string(),
        checks: Vec::new(),
        components: vec![
            component("Website", "svc-web-internal", Some(MID_PPM)),
            component("API", "svc-api-internal", None),
            component("Mail", "svc-mail-internal", Some(HIGH_PPM)),
        ],
    }
}


fn state(tenant: &str, service: &str, value: ComponentState) -> ServiceState {
    ServiceState {
        tenant: tenant.to_string(),
        service: service.to_string(),
        state: value,
    }
}


fn figure(tenant: &str, service: &str, availability_ppm: Option<u32>) -> FigureInput {
    FigureInput {
        tenant: tenant.to_string(),
        service: service.to_string(),
        availability_ppm,
    }
}


fn incident(service: &str, published: bool, title: &str, started_at: i64) -> IncidentInput {
    IncidentInput {
        tenant: TENANT.to_string(),
        service: service.to_string(),
        published,
        public_title: title.to_string(),
        started_at,
        resolved_at: Some(started_at + 1),
        updates: vec![IncidentUpdateInput {
            at: started_at,
            message: "We are investigating".to_string(),
            internal_note: SECRET_NOTE.to_string(),
        }],
        omitted_updates: 0,
        internal_note: SECRET_NOTE.to_string(),
        assignee: "alice".to_string(),
        asset_ids: vec![ASSET.to_string()],
        addresses: vec!["10.0.0.5".to_string()],
    }
}


fn all_states() -> Vec<ServiceState> {
    vec![
        state(TENANT, "svc-web-internal", ComponentState::Operational),
        state(TENANT, "svc-api-internal", ComponentState::Degraded),
        state(TENANT, "svc-mail-internal", ComponentState::Maintenance),
    ]
}


#[test]
fn undeclared_service_is_dropped_and_counted() -> TestResult {
    let mut states = all_states();
    states.push(state(TENANT, "svc-secret", ComponentState::MajorOutage));
    states.push(state(TENANT, "svc-web-internal", ComponentState::MajorOutage));
    let incidents = vec![
        incident("svc-secret", true, "Hidden", 1),
        incident("svc-web-internal", true, "Visible", LATER),
    ];
    let figures = vec![figure(TENANT, "svc-secret", Some(1)), figure(TENANT, "svc-web-internal", Some(HIGH_PPM))];
    let page = render(&config(), &states, &incidents, &figures, NOW, &DEFAULT_LIMITS)?;
    assert_eq!(page.dropped.states, DROPPED_STATES);
    assert_eq!(page.dropped.incidents, 1);
    assert_eq!(page.dropped.figures, 1);
    assert!(!page.json.contains("Hidden"));
    assert!(page.json.contains("Visible"));
    assert!(!page.json.contains("svc-"));
    assert!(!page.html.contains("svc-"));
    assert!(page.json.contains("\"Website\""));
    Ok(())
}


#[test]
fn unpublished_and_internal_data_never_appear() -> TestResult {
    let incidents = vec![
        incident("svc-web-internal", false, "Draft", 1),
        incident("svc-api-internal", true, "Public", LATER),
    ];
    let page = render(&config(), &all_states(), &incidents, &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(page.dropped.incidents, 0);
    assert!(!page.json.contains("Draft"));
    assert!(!page.html.contains("Draft"));
    [SECRET_NOTE, "10.0.0.5", ASSET, "alice", "svc-"]
        .iter()
        .for_each(|needle| assert!(!page.json.contains(needle) && !page.html.contains(needle)));
    assert!(page.json.contains("We are investigating"));
    Ok(())
}


#[test]
fn html_injection_is_escaped() -> TestResult {
    let mut hostile = incident("svc-web-internal", true, "<script>alert(1)</script>", 1);
    hostile.updates.push(IncidentUpdateInput {
        at: LATER,
        message: "<img src=x onerror=1> & more".to_string(),
        internal_note: String::new(),
    });
    let mut page_config = config();
    page_config.title = "<b>T</b>".to_string();
    page_config.components.push(component("<i>Odd</i>", "svc-odd", None));
    let page = render(&page_config, &[], &[hostile], &[], NOW, &DEFAULT_LIMITS)?;
    assert!(!page.html.contains("<script>"));
    assert!(!page.html.contains("<img"));
    assert!(!page.html.contains("<b>T"));
    assert!(!page.html.contains("<i>Odd"));
    assert!(page.html.contains("&lt;script&gt;"));
    assert!(page.html.contains("&amp; more"));
    Ok(())
}


#[test]
fn output_over_the_bound_is_refused() -> TestResult {
    let json_small = Limits {
        max_json_bytes: SMALL,
        ..DEFAULT_LIMITS
    };
    let html_small = Limits {
        max_html_bytes: SMALL,
        ..DEFAULT_LIMITS
    };
    let json_result = render(&config(), &[], &[], &[], NOW, &json_small);
    let html_result = render(&config(), &[], &[], &[], NOW, &html_small);
    assert!(matches!(json_result, Err(StatusPageError::OutputTooLarge { format: "json", .. })));
    assert!(matches!(html_result, Err(StatusPageError::OutputTooLarge { format: "html", .. })));
    Ok(())
}


#[test]
fn rendering_is_byte_identical_and_ordered() -> TestResult {
    let incidents = vec![
        incident("svc-web-internal", true, "B", 1),
        incident("svc-api-internal", true, "A", 1),
        incident("svc-mail-internal", true, "Newest", NEWEST),
    ];
    let first = render(&config(), &all_states(), &incidents, &[], NOW, &DEFAULT_LIMITS)?;
    let second = render(&config(), &all_states(), &incidents, &[], NOW, &DEFAULT_LIMITS)?;
    assert_eq!(first, second);
    let newest = first.json.find("Newest");
    let older = first.json.find("\"A\"");
    assert!(newest < older);
    Ok(())
}


#[test]
fn mixed_tenants_are_refused() -> TestResult {
    let foreign_state = vec![state("other", "svc-web-internal", ComponentState::Operational)];
    let mut foreign_incident = incident("svc-web-internal", true, "X", 1);
    foreign_incident.tenant = "other".to_string();
    let foreign_figure = vec![figure("other", "svc-web-internal", None)];
    let results = [
        render(&config(), &foreign_state, &[], &[], NOW, &DEFAULT_LIMITS),
        render(&config(), &[], &[foreign_incident], &[], NOW, &DEFAULT_LIMITS),
        render(&config(), &[], &[], &foreign_figure, NOW, &DEFAULT_LIMITS),
    ];
    assert!(results.iter().all(|result| matches!(result, Err(StatusPageError::TenantMismatch))));
    Ok(())
}


#[test]
fn worst_state_and_maintenance_ordering() -> TestResult {
    let worst = worst_state(
        [
            ComponentState::Degraded,
            ComponentState::MajorOutage,
            ComponentState::PartialOutage,
            ComponentState::Maintenance,
        ]
        .into_iter(),
    );
    assert_eq!(worst, ComponentState::MajorOutage);
    assert_eq!(worst_state([ComponentState::Maintenance].into_iter()), ComponentState::Unknown);
    let page = render(&config(), &all_states(), &[], &[], NOW, &DEFAULT_LIMITS)?;
    assert!(page.json.contains("\"state\":\"degraded\",\"maintenance\":true"));
    assert!(page.html.contains("Maintenance in progress."));
    let calm = render(&config(), &[], &[], &[], NOW, &DEFAULT_LIMITS)?;
    assert!(calm.json.contains("\"state\":\"unknown\",\"maintenance\":false"));
    assert!(!calm.html.contains("Maintenance in progress."));
    Ok(())
}


#[test]
fn figures_and_labels() -> TestResult {
    let figures = vec![
        figure(TENANT, "svc-web-internal", Some(HIGH_PPM)),
        figure(TENANT, "svc-api-internal", Some(LOW_PPM)),
        figure(TENANT, "svc-mail-internal", Some(LOW_PPM)),
    ];
    let page = render(&config(), &all_states(), &[], &figures, NOW, &DEFAULT_LIMITS)?;
    assert!(page.json.contains("\"objective_met\":true"));
    assert!(page.json.contains("\"objective_met\":false"));
    assert!(page.json.contains("\"objective_met\":null"));
    assert!(page.html.contains("99.9900% (objective 99.9000%)"));
    assert_eq!(percent_text(LOW_PPM), "99.0000%");
    let unmeasured = PublicFigure {
        availability_ppm: None,
        objective_ppm: None,
        objective_met: None,
    };
    assert_eq!(figure_text(&unmeasured), "n/a");
    let labels: Vec<&str> = [
        ComponentState::Operational,
        ComponentState::Degraded,
        ComponentState::PartialOutage,
        ComponentState::MajorOutage,
        ComponentState::Maintenance,
        ComponentState::Unknown,
    ]
    .into_iter()
    .map(state_label)
    .collect();
    assert_eq!(labels.len(), ALL_STATES);
    assert!(labels.iter().all(|label| !label.is_empty()));
    Ok(())
}


#[test]
fn bounds_are_enforced() -> TestResult {
    let tight_text = Limits {
        max_text_bytes: TEXT_LIMIT,
        ..DEFAULT_LIMITS
    };
    let mut long_title = incident("svc-web-internal", true, "short", 1);
    long_title.public_title = "x".repeat(TEXT_LIMIT + 1);
    let mut long_message = incident("svc-web-internal", true, "short", 1);
    long_message.updates.first_mut().ok_or("update")?.message = "y".repeat(TEXT_LIMIT + 1);
    let mut many_updates = incident("svc-web-internal", true, "t", 1);
    many_updates.updates.push(many_updates.updates.first().ok_or("update")?.clone());
    let one_update = Limits {
        max_updates: 1,
        ..DEFAULT_LIMITS
    };
    let one_incident = Limits {
        max_incidents: 1,
        ..DEFAULT_LIMITS
    };
    let one_component = Limits {
        max_components: 1,
        ..DEFAULT_LIMITS
    };
    let three_states = all_states();
    let mut four_states = all_states();
    four_states.push(state(TENANT, "svc-x", ComponentState::Unknown));
    let four_figures: Vec<FigureInput> = ["a", "b", "c", "d"].iter().map(|service| figure(TENANT, service, None)).collect();
    let three_components = Limits {
        max_components: THREE,
        ..DEFAULT_LIMITS
    };
    let results = [
        render(&config(), &[], &[long_title], &[], NOW, &tight_text),
        render(&config(), &[], &[long_message], &[], NOW, &tight_text),
        render(&config(), &[], &[many_updates], &[], NOW, &one_update),
        render(
            &config(),
            &[],
            &[incident("a", true, "t", 1), incident("a", true, "t", 1)],
            &[],
            NOW,
            &one_incident,
        ),
        render(&config(), &three_states, &[], &[], NOW, &one_component),
        render(&config(), &[], &[], &four_figures, NOW, &three_components),
        render(&config(), &four_states, &[], &[], NOW, &three_components),
    ];
    let expected = [
        (true, "incident title"),
        (true, "incident message"),
        (false, "updates"),
        (false, "incidents"),
        (false, "components"),
        (false, "figures"),
        (false, "states"),
    ];
    let seen: Vec<(bool, &str)> = results
        .iter()
        .map(|result| match result {
            Err(StatusPageError::TextTooLong { field, .. }) => (true, *field),
            Err(StatusPageError::TooMany { what, .. }) => (false, *what),
            _ => (false, "other"),
        })
        .collect();
    assert_eq!(seen, expected);
    Ok(())
}


const CUT_UPDATES: usize = 3;


const UNLISTED: usize = 2;


#[test]
fn a_cut_of_updates_and_of_undeclared_incidents_is_stated_never_silent() -> TestResult {
    let plain = render(
        &config(),
        &[],
        &[incident("svc-web-internal", true, "Plain", 1)],
        &[],
        NOW,
        &DEFAULT_LIMITS,
    )?;
    assert!(!plain.json.contains("omitted_updates") && !plain.json.contains("omitted_undeclared"));
    assert!(!plain.html.contains("older updates") && !plain.html.contains("does not list"));
    let mut cut = incident("svc-web-internal", true, "Cut", 1);
    cut.omitted_updates = CUT_UPDATES;
    let omitted = Omitted {
        all: UNLISTED,
        ongoing: 0,
        undeclared: UNLISTED,
        reason: "undeclared",
    };
    let page = render_omitting(&config(), &[], &[cut], &[], NOW, &DEFAULT_LIMITS, omitted)?;
    assert!(page.json.contains("\"omitted_updates\":3") && page.json.contains("\"omitted_undeclared\":2"));
    assert!(page.html.contains("3 older updates not shown.") && page.html.contains("2 of them on services this page does not list."));
    assert!(page.json.contains("\"omitted_incidents\":2"));
    Ok(())
}
