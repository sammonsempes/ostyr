pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub type RemovalPlan = Vec<(software_catalog::model::ActionKind, Vec<String>)>;
