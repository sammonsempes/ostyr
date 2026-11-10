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
    #[error("the address form is refused")]
    AddressForm,
    #[error("the TLS setup is refused")]
    Tls(#[source] rustls::Error),
    #[error("the CA certificate is refused")]
    SmtpCertificate(#[source] rustls_pki_types::pem::Error),
    #[error("the CA file holds no certificate")]
    NoCertificate,
    #[error("the relay host is not a valid server name")]
    InvalidHost(#[source] rustls_pki_types::InvalidDnsNameError),
    #[error("the connection failed")]
    Io(#[source] std::io::Error),
    #[error("no relay address was tried")]
    NoAddress,
    #[error("the send did not finish before the deadline")]
    Deadline,
    #[error("the server closed the connection")]
    Closed,
    #[error("the server reply is larger than the bound")]
    ReplyTooLong,
    #[error("the server reply is malformed")]
    ReplyFormat,
    #[error("the server refused a command with code {code}")]
    Rejected { code: u16 },
    #[error("the server does not offer STARTTLS")]
    NoStarttls,
    #[error("the server does not offer AUTH PLAIN")]
    NoAuth,
}


/// Fixed texts: nothing derived from the key or the MAC reaches an error.
#[derive(Debug, Error)]
pub enum LinkError<UsedError: std::error::Error + 'static> {
    #[error("the link is malformed")]
    Malformed,
    #[error("the link is not valid")]
    Tampered,
    #[error("the link has expired")]
    Expired,
    #[error("the link was already used")]
    Reused,
    #[error("the link belongs to another tenant")]
    OtherTenant,
    #[error("the tenant name is not valid")]
    InvalidTenant,
    #[error("no random bytes are available")]
    Random(#[source] getrandom::Error),
    #[error("the link key cannot be used")]
    Key(#[source] hmac::digest::InvalidLength),
    #[error("the used-link store failed")]
    Used(#[source] UsedError),
    #[error("the alert store refused the event")]
    Alert(#[source] StoreError),
}


#[derive(Debug, Error)]
pub enum KeyError {
    #[error(transparent)]
    File(#[from] core_pg::error::PgError),
    #[error("the key file cannot be inspected")]
    Inspect(#[source] std::io::Error),
    #[error("the key file grants access to group or other")]
    Mode,
    #[error("the key file is not owned by the service user")]
    Owner,
    #[error("the key is shorter than {min} bytes")]
    TooShort { min: usize },
}


#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("the alert is resolved and accepts no event")]
    Resolved,
    #[error("the alert is already acknowledged")]
    AlreadyAcknowledged,
    #[error("escalation must go to level {expected}, not {requested}")]
    WrongLevel { expected: u32, requested: u32 },
    #[error("level {requested} is above the limit {max}")]
    LevelLimit { requested: u32, max: u32 },
}


#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Pg(#[from] core_pg::error::PgError),
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    #[error("the fingerprint is empty, longer than {max} bytes or holds a control character")]
    InvalidFingerprint { max: usize },
    #[error("the channel name is empty, longer than {max} bytes or holds a control character")]
    InvalidChannel { max: usize },
    #[error("the limit {limit} is not between 1 and {max}")]
    LimitOutOfRange { limit: u32, max: u32 },
    #[error("no such alert for this tenant")]
    NotFound,
    #[error("the alert was changed by someone else")]
    Conflict,
    #[error("the database returned an unexpected value for `{column}`")]
    BadRow { column: &'static str },
}
