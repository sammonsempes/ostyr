use core_config::error::ConfigError;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum OncallError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{file}: larger than {max} bytes")]
    FileTooLarge { file: String, max: u64 },
    #[error("{what}: {value} is outside {min}..={max}")]
    OutOfBounds { what: &'static str, value: u64, min: u64, max: u64 },
    #[error("override of `{person}` ends before it starts")]
    OverrideRange { person: String },
    #[error("`{name}` ends before it starts")]
    ExpiryRange { name: String },
    #[error("invalid regex `{pattern}`")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("channel `{channel}`: {reason}")]
    InvalidChannel { channel: String, reason: &'static str },
    #[error("the setting `{field}` is not valid")]
    InvalidSetting { field: &'static str },
    #[error("`{field}` holds a CR or LF")]
    HeaderInjection { field: &'static str },
}


/// The text of each variant never holds the target, a header or a secret.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("the channel kind is not sent over https")]
    NotHttps,
    #[error("the target is not an https URL")]
    Target,
    #[error("the text holds a forbidden character")]
    ForbiddenChar,
    #[error("no secrets directory for the tenant")]
    NoSecretsDir,
    #[error("the secret file is refused")]
    SecretFile(#[source] std::io::Error),
    #[error("the secret file is larger than {max} bytes")]
    SecretTooLarge { max: u64 },
    #[error("the secret is empty or not printable text")]
    SecretFormat,
    #[error("the CA file is refused")]
    CaFile(#[source] Box<OncallError>),
    #[error("the CA certificate is refused")]
    Certificate(#[source] ureq::Error),
    #[error("the request failed")]
    Request(#[source] ureq::Error),
    #[error("the receiver did not answer with a success status")]
    Status,
    #[error("the settings have no smtp section")]
    SmtpNotConfigured,
    #[error("the address is refused")]
    Address(#[source] lettre::address::AddressError),
    #[error("the text is too large or holds a line break in the subject")]
    MailText,
    #[error("the channel has a secret file but the settings no smtp username")]
    NoUsername,
    #[error("the mail cannot be built")]
    Build(#[source] lettre::error::Error),
    #[error("the TLS setup is refused")]
    Tls(#[source] lettre::transport::smtp::Error),
    #[error("the CA certificate is refused")]
    SmtpCertificate(#[source] lettre::transport::smtp::Error),
    #[error("the mail was not delivered")]
    Smtp(#[source] lettre::transport::smtp::Error),
    #[error("the send did not finish before the deadline")]
    Deadline(#[source] std::sync::mpsc::RecvTimeoutError),
}
