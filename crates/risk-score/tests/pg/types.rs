use risk_score::error::RiskError;
use risk_score::source::Outcome;


pub type Running = tokio::task::JoinHandle<Result<Outcome, RiskError>>;
