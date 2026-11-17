use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum WafError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{count} routes exceed the limit of {max}")]
    TooManyRoutes { count: usize, max: usize },
    #[error("the rendered configuration of {bytes} bytes exceeds the limit of {max}")]
    OutputTooLarge { bytes: usize, max: usize },
    #[error("invalid tls section: {0}")]
    BadTls(&'static str),
    #[error("cannot read the ACME CA root file")]
    CaRoot(#[source] std::io::Error),
    #[error("untrusted CA root directory: {0}")]
    BadCaDir(&'static str),
    #[error("cannot write the CA root file")]
    CaWrite(#[source] std::io::Error),
    #[error("cannot write the output")]
    Output(#[from] std::io::Error),
    #[error("cannot encode the configuration")]
    Encode(#[from] serde_json::Error),
}
