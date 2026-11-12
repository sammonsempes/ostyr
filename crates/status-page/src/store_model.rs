/// A bound value; the tenant is bound as `$1` by the executor, these start at `$2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Int(i64),
    Text(String),
    Bool(bool),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Int(i64),
    Text(String),
    Null,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub sql: &'static str,
    pub params: Vec<Param>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIncident {
    pub service: String,
    pub title: String,
    pub published: bool,
    pub started_at: i64,
    pub internal_note: String,
}


/// An incident id with the version the next write must present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentRef {
    pub id: i64,
    pub version: i64,
}


/// What one read of the store gives: the incidents within the limit and the exact counts of the tenant's published incidents.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublishedRead {
    pub incidents: Vec<crate::model::IncidentInput>,
    pub total: usize,
    pub ongoing: usize,
}
