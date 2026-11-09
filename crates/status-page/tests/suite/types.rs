pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub type Clock = std::sync::Arc<std::sync::atomic::AtomicU64>;
