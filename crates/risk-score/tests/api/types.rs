pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Flown = Result<std::sync::Arc<risk_score::api_model::Computed>, risk_score::api_model::Unavailable>;
