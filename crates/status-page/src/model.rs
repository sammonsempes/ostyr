use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentConfig {
    pub name: String,
    pub service: String,
    pub objective_ppm: Option<u32>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageConfig {
    pub id: String,
    pub tenant: String,
    pub title: String,
    pub components: Vec<ComponentConfig>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_components: usize,
    pub max_incidents: usize,
    pub max_updates: usize,
    pub max_text_bytes: usize,
    pub max_json_bytes: usize,
    pub max_html_bytes: usize,
}


pub const DEFAULT_LIMITS: Limits = Limits {
    max_components: 200,
    max_incidents: 500,
    max_updates: 100,
    max_text_bytes: 2048,
    max_json_bytes: 1_048_576,
    max_html_bytes: 2_097_152,
};


/// Declaration order is the severity order; `Maintenance` and `Unknown` never count in the worst state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Operational,
    Degraded,
    PartialOutage,
    MajorOutage,
    Maintenance,
    Unknown,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub tenant: String,
    pub service: String,
    pub state: ComponentState,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentUpdateInput {
    pub at: i64,
    pub message: String,
    pub internal_note: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentInput {
    pub tenant: String,
    pub service: String,
    pub published: bool,
    pub public_title: String,
    pub started_at: i64,
    pub resolved_at: Option<i64>,
    pub updates: Vec<IncidentUpdateInput>,
    pub internal_note: String,
    pub assignee: String,
    pub asset_ids: Vec<String>,
    pub addresses: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FigureInput {
    pub tenant: String,
    pub service: String,
    pub availability_ppm: Option<u32>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicFigure {
    pub availability_ppm: Option<u32>,
    pub objective_ppm: Option<u32>,
    pub objective_met: Option<bool>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicComponent {
    pub name: String,
    pub state: ComponentState,
    pub figure: Option<PublicFigure>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicUpdate {
    pub at: i64,
    pub message: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicIncident {
    pub title: String,
    pub component: String,
    pub started_at: i64,
    pub resolved_at: Option<i64>,
    pub updates: Vec<PublicUpdate>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicPage {
    pub id: String,
    pub title: String,
    pub generated_at: i64,
    pub state: ComponentState,
    pub maintenance: bool,
    pub components: Vec<PublicComponent>,
    pub incidents: Vec<PublicIncident>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    pub states: usize,
    pub incidents: usize,
    pub figures: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    pub json: String,
    pub html: String,
    pub dropped: Dropped,
}
