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
}
