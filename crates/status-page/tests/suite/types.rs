pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub type Clock = std::sync::Arc<std::sync::atomic::AtomicU64>;


pub type Server = (
    std::net::SocketAddr,
    std::sync::Arc<status_page::model::PageState>,
    tokio::sync::oneshot::Sender<()>,
);
