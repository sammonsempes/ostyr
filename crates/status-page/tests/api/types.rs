pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Outcome = fn() -> Result<status_page::store_model::IncidentRef, status_page::error::StoreError>;


pub type Calls = std::sync::Arc<std::sync::Mutex<Vec<String>>>;
