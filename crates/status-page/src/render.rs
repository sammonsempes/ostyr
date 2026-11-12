use crate::config::{check_count, check_text, validate_config};
use crate::error::StatusPageError;
use crate::html::render_html;
use crate::model::{
    ComponentState, Dropped, FigureInput, IncidentInput, Limits, PageConfig, PublicComponent, PublicFigure, PublicIncident, PublicPage, PublicUpdate,
    RenderedPage, ServiceState,
};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};


pub fn is_ranked(state: ComponentState) -> bool {
    matches!(
        state,
        ComponentState::Operational | ComponentState::Degraded | ComponentState::PartialOutage | ComponentState::MajorOutage
    )
}


pub fn worst_state(states: impl Iterator<Item = ComponentState>) -> ComponentState {
    states.filter(|state| is_ranked(*state)).max().unwrap_or(ComponentState::Unknown)
}


pub fn check_inputs(
    config: &PageConfig,
    states: &[ServiceState],
    incidents: &[IncidentInput],
    figures: &[FigureInput],
    limits: &Limits,
) -> Result<(), StatusPageError> {
    let same_tenant = states.iter().all(|state| state.tenant == config.tenant)
        && incidents.iter().all(|incident| incident.tenant == config.tenant)
        && figures.iter().all(|figure| figure.tenant == config.tenant);
    check_count("states", states.len(), limits.max_components)?;
    check_count("figures", figures.len(), limits.max_components)?;
    check_count("incidents", incidents.len(), limits.max_incidents)?;
    incidents
        .iter()
        .try_for_each(|incident| check_count("updates", incident.updates.len(), limits.max_updates))?;
    if same_tenant {
        Ok(())
    } else {
        Err(StatusPageError::TenantMismatch)
    }
}


/// Keeps the first entry of every declared service; undeclared and repeated ones are counted as dropped.
pub fn index_declared<'a, Item>(entries: impl Iterator<Item = (&'a str, Item)>, declared: &BTreeSet<&str>) -> (BTreeMap<&'a str, Item>, usize) {
    entries.fold((BTreeMap::new(), 0), |(mut kept, dropped), (service, item)| {
        if declared.contains(service) && !kept.contains_key(service) {
            kept.entry(service).or_insert(item);
            (kept, dropped)
        } else {
            (kept, dropped + 1)
        }
    })
}


pub fn public_figure(availability_ppm: Option<u32>, objective_ppm: Option<u32>) -> PublicFigure {
    PublicFigure {
        availability_ppm,
        objective_ppm,
        objective_met: availability_ppm.zip(objective_ppm).map(|(measured, objective)| measured >= objective),
    }
}


pub fn public_incident(incident: &IncidentInput, component: &str) -> PublicIncident {
    PublicIncident {
        title: incident.public_title.clone(),
        component: component.to_string(),
        started_at: incident.started_at,
        resolved_at: incident.resolved_at,
        updates: incident
            .updates
            .iter()
            .map(|update| PublicUpdate {
                at: update.at,
                message: update.message.clone(),
            })
            .collect(),
    }
}


pub fn check_incident_text(incident: &PublicIncident, limit: usize) -> Result<(), StatusPageError> {
    check_text("incident title", &incident.title, limit)?;
    incident
        .updates
        .iter()
        .try_for_each(|update| check_text("incident message", &update.message, limit))
}


pub fn check_output(format: &'static str, text: &str, limit: usize) -> Result<(), StatusPageError> {
    if text.len() > limit {
        Err(StatusPageError::OutputTooLarge { format, limit })
    } else {
        Ok(())
    }
}


/// Renders both documents; `now` is the generation time, an input.
pub fn render(
    config: &PageConfig,
    states: &[ServiceState],
    incidents: &[IncidentInput],
    figures: &[FigureInput],
    now: i64,
    limits: &Limits,
) -> Result<RenderedPage, StatusPageError> {
    render_omitting(config, states, incidents, figures, now, limits, (0, 0))
}


/// As `render`, and the page states that `omitted` incidents (`.0`, of which `.1` are ongoing) are not shown.
pub fn render_omitting(
    config: &PageConfig,
    states: &[ServiceState],
    incidents: &[IncidentInput],
    figures: &[FigureInput],
    now: i64,
    limits: &Limits,
    omitted: (usize, usize),
) -> Result<RenderedPage, StatusPageError> {
    validate_config(config, limits)?;
    check_inputs(config, states, incidents, figures, limits)?;
    let declared: BTreeSet<&str> = config.components.iter().map(|component| component.service.as_str()).collect();
    let (state_by_service, dropped_states) = index_declared(states.iter().map(|state| (state.service.as_str(), state.state)), &declared);
    let (figure_by_service, dropped_figures) =
        index_declared(figures.iter().map(|figure| (figure.service.as_str(), figure.availability_ppm)), &declared);
    let names: BTreeMap<&str, &str> = config
        .components
        .iter()
        .map(|component| (component.service.as_str(), component.name.as_str()))
        .collect();
    let published: Vec<&IncidentInput> = incidents.iter().filter(|incident| incident.published).collect();
    let mut public_incidents: Vec<PublicIncident> = published
        .iter()
        .filter_map(|incident| names.get(incident.service.as_str()).map(|name| public_incident(incident, name)))
        .collect();
    public_incidents.sort_by_key(|incident| (Reverse(incident.started_at), incident.title.clone(), incident.component.clone()));
    public_incidents
        .iter()
        .try_for_each(|incident| check_incident_text(incident, limits.max_text_bytes))?;
    let components: Vec<PublicComponent> = config
        .components
        .iter()
        .map(|component| PublicComponent {
            name: component.name.clone(),
            state: state_by_service
                .get(component.service.as_str())
                .copied()
                .unwrap_or(ComponentState::Unknown),
            figure: figure_by_service
                .get(component.service.as_str())
                .map(|availability| public_figure(*availability, component.objective_ppm)),
        })
        .collect();
    let page = PublicPage {
        id: config.id.clone(),
        title: config.title.clone(),
        generated_at: now,
        state: worst_state(components.iter().map(|component| component.state)),
        maintenance: components.iter().any(|component| component.state == ComponentState::Maintenance),
        components,
        incidents: public_incidents,
        omitted_incidents: omitted.0,
        omitted_ongoing: omitted.1,
    };
    let json = serde_json::to_string(&page)?;
    check_output("json", &json, limits.max_json_bytes)?;
    let html = render_html(&page);
    check_output("html", &html, limits.max_html_bytes)?;
    let dropped = Dropped {
        states: dropped_states,
        incidents: published.len() - page.incidents.len(),
        figures: dropped_figures,
    };
    Ok(RenderedPage { json, html, dropped })
}
