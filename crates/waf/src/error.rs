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
    #[error("the ACME CA root file is untrusted or unreadable")]
    CaRoot(#[source] ConfigError),
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
    #[cfg(target_os = "linux")]
    #[error("the Caddy program /usr/bin/caddy is untrusted")]
    Program(#[source] core_config::trusted_program::TrustedProgramError),
    #[error("caddy {step} not started: the program changed or is untrusted")]
    ProgramChanged { step: &'static str },
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
    #[error("cannot open the audit sink")]
    NoSink(#[source] core_audit::error::AuditError),
    #[error("cannot open the audit sink ({sink}) and the start is refused: {refusal}")]
    NoSinkAndRefused {
        #[source]
        sink: Box<core_audit::error::AuditError>,
        refusal: Box<core_config::error::ConfigError>,
    },
    #[error("cannot audit the first configuration")]
    Audit(#[source] core_audit::error::AuditError),
}


#[cfg(unix)]
impl From<rustix::io::Errno> for DeliverError {
    fn from(errno: rustix::io::Errno) -> Self {
        Self::Write(errno.into())
    }
}


/// Why `ostyr-waf` stopped; every text is fixed.
#[derive(Debug, Error)]
pub enum ServeError {
    #[error("usage: ostyr-waf <settings.yaml>")]
    Usage,
    #[error("cannot install the log subscriber")]
    Logging(#[from] tracing::subscriber::SetGlobalDefaultError),
    #[error("the settings file was refused")]
    Settings(#[from] core_config::error::ConfigError),
    #[error("the settings file names no audit_file")]
    NoAuditFile,
    #[error("audit_file changed between two reads of the settings file")]
    AuditPathChanged,
    #[error("the start was refused")]
    Open(#[from] OpenError),
    #[error("cannot watch the settings and routes files")]
    Watch(#[from] core_config::error::WatchError),
    #[error("cannot wait for signals")]
    Signal(#[from] std::io::Error),
}
