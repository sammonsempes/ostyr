use serde::Serialize;
use utoipa::ToSchema;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssetCounts {
    pub keys: u64,
    pub attributes: u64,
    pub open_conflicts: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssetSummary {
    pub id: String,
    pub kind: String,
    pub lifecycle: String,
    pub version: u64,
    pub counts: AssetCounts,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct KeyView {
    pub key: String,
    pub value: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AttributeView {
    pub name: String,
    pub value: String,
    pub source: String,
}


/// `truncated` is true when `keys` or `attributes` hold fewer entries than `counts` says; the first ones by name are shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssetDetail {
    #[serde(flatten)]
    pub summary: AssetSummary,
    pub keys: Vec<KeyView>,
    pub attributes: Vec<AttributeView>,
    pub truncated: bool,
}


/// `after` is the id of the last asset of the previous page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPage {
    pub after: Option<String>,
    pub size: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryList {
    pub summaries: Vec<AssetSummary>,
    pub next: Option<String>,
}
