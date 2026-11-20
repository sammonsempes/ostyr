pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub const OPERATIONS: usize = 3;


pub const DEADLINE_RESOLVE: usize = 2;


pub type Outcomes = [Result<status_page::store_model::IncidentRef, status_page::error::StoreError>; OPERATIONS];
