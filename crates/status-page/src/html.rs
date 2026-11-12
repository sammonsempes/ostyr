use crate::model::{ComponentState, PublicComponent, PublicFigure, PublicIncident, PublicPage};
use html_escape::encode_text;


const PPM_PER_PERCENT: u32 = 10_000;


pub fn state_label(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Operational => "Operational",
        ComponentState::Degraded => "Degraded performance",
        ComponentState::PartialOutage => "Partial outage",
        ComponentState::MajorOutage => "Major outage",
        ComponentState::Maintenance => "Under maintenance",
        ComponentState::Unknown => "Unknown",
    }
}


pub fn percent_text(ppm: u32) -> String {
    format!("{}.{:04}%", ppm / PPM_PER_PERCENT, ppm % PPM_PER_PERCENT)
}


pub fn figure_text(figure: &PublicFigure) -> String {
    let measured = figure.availability_ppm.map_or_else(|| "n/a".to_string(), percent_text);
    let objective = figure
        .objective_ppm
        .map_or_else(String::new, |ppm| format!(" (objective {})", percent_text(ppm)));
    format!("{measured}{objective}")
}


pub fn component_item(component: &PublicComponent) -> String {
    let figure = component
        .figure
        .as_ref()
        .map_or_else(String::new, |figure| format!(", {}", figure_text(figure)));
    format!("<li>{}: {}{}</li>", encode_text(&component.name), state_label(component.state), figure)
}


pub fn incident_item(incident: &PublicIncident) -> String {
    let updates: String = incident
        .updates
        .iter()
        .map(|update| format!("<li>{}: {}</li>", update.at, encode_text(&update.message)))
        .collect();
    format!(
        "<li><h3>{}</h3><p>{}, started {}</p><ul>{}</ul></li>",
        encode_text(&incident.title),
        encode_text(&incident.component),
        incident.started_at,
        updates
    )
}


pub fn render_html(page: &PublicPage) -> String {
    let components: String = page.components.iter().map(component_item).collect();
    let incidents: String = page.incidents.iter().map(incident_item).collect();
    let title = encode_text(&page.title);
    let omitted = if page.omitted_incidents == 0 {
        String::new()
    } else {
        format!("<p>{} older incidents not shown.</p>", page.omitted_incidents)
    };
    let maintenance = if page.maintenance { "<p>Maintenance in progress.</p>" } else { "" };
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1>\
         <p>{}</p>{maintenance}<ul>{components}</ul><h2>Incidents</h2><ul>{incidents}</ul>{omitted}<p>Generated at {}</p></body></html>",
        state_label(page.state),
        page.generated_at
    )
}
