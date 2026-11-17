use risk_score::error::RiskError;
use risk_score::source::Outcome;
use std::sync::Arc;


pub type Shape = (usize, i32, Vec<Vec<Vec<u8>>>);


pub type Handler = Arc<dyn Fn(&str) -> crate::fake::Reply + Send + Sync>;


pub type Running = tokio::task::JoinHandle<Result<Outcome, RiskError>>;
