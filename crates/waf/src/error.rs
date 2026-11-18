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


/// A refused delivery to Caddy; every text is fixed, Caddy's own output is never read.
#[derive(Debug, Error)]
pub enum DeliverError {
    #[cfg(unix)]
    #[error(transparent)]
    OutDir(#[from] core_config::trusted_dir::TrustedDirError),
    #[error("the rendered file name is taken by something that is not a regular file")]
    BadTarget,
    #[error("cannot write the rendered file")]
    Write(#[source] std::io::Error),
    #[error("cannot publish the rendered file after caddy loaded it, the running configuration may differ")]
    Publish(#[source] std::io::Error),
    #[error(transparent)]
    CaRoot(WafError),
    #[error("cannot run caddy {step}")]
    Spawn {
        step: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("caddy {step} failed with exit status {code:?}")]
    Failed { step: &'static str, code: Option<i32> },
    #[error("caddy {step} exceeded {seconds} seconds")]
    TimedOut { step: &'static str, seconds: u64 },
    #[error("caddy {step} did not finish and the running configuration is unknown")]
    Unknown { step: &'static str },
    #[error("untrusted admin socket directory")]
    AdminDir(#[source] WafError),
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] core_config::error::ConfigError),
    #[error("the first configuration was refused")]
    Deliver(#[from] DeliverError),
    #[error("cannot audit the first configuration")]
    Audit(#[source] core_audit::error::AuditError),
}


#[cfg(unix)]
impl From<rustix::io::Errno> for DeliverError {
    fn from(errno: rustix::io::Errno) -> Self {
        Self::Write(errno.into())
    }
}
