use thiserror::Error;


#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlatformError {
    #[error("route {0} is declared twice")]
    DuplicateRoute(String),
    #[error("settings.modules is required")]
    MissingModules,
    #[error("settings.modules is empty")]
    EmptyModules,
    #[error("settings.modules is longer than {limit} characters")]
    ModulesTooLong { limit: usize },
    #[error("settings.modules entry {index} is not a known module")]
    UnknownModule { index: usize },
    #[error("settings.modules entry {index} repeats an earlier module")]
    DuplicateModule { index: usize },
    #[error("settings.risk.weights_file is required by the risk module")]
    MissingWeightsFile,
    #[error("settings.status.page_file is required by the status module")]
    MissingPageFile,
    #[error("settings.status.page_file {reason}")]
    PageFile { reason: &'static str },
    #[error("settings.status.page_file tenant differs from the module file tenant")]
    PageTenantMismatch,
    #[error("settings.traces.settings_file is required by the traces module")]
    MissingTracesSettings,
    #[error("settings.traces.sampling_file is required by the traces module")]
    MissingTracesSampling,
    #[error("settings.otlp.senders_file is required by the traces module")]
    MissingSendersFile,
    #[error("the traces module needs settings.tls_certificate and settings.tls_key: tokens never travel in clear")]
    TlsRequired,
    #[error("the traces module has no runtime")]
    MissingTracesRuntime,
    #[error("a selected module has no connection semaphore")]
    MissingPermits,
}
