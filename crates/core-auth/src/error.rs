use core_audit::error::AuditError;
use core_config::error::ConfigError;
use std::io;
use thiserror::Error;
use time::OffsetDateTime;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PolicyViolation {
    #[error("password is shorter than the minimum length")]
    TooShort,
    #[error("password is longer than the maximum length")]
    TooLong,
    #[error("password appears in the compromised-password list")]
    Compromised,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OidcDenial {
    #[error("the login state is unknown or expired")]
    BadState,
    #[error("the identity provider failed or answered invalidly")]
    Provider,
    #[error("the provider returned no ID token")]
    MissingIdToken,
    #[error("the ID token has expired")]
    Expired,
    #[error("the ID token audience is wrong")]
    WrongAudience,
    #[error("the ID token issuer is wrong")]
    WrongIssuer,
    #[error("the ID token nonce does not match")]
    BadNonce,
    #[error("the ID token signature is invalid")]
    BadSignature,
    #[error("the ID token is invalid")]
    InvalidToken,
    #[error("the ID token subject is unusable")]
    InvalidSubject,
    #[error("no group of the user maps to a role")]
    Unmapped,
    #[error("too many logins are pending")]
    TooManyPending,
    #[error("the ID token does not prove multi-factor authentication")]
    MfaMissing,
}


#[derive(Debug, Error)]
pub enum AuthError {
    #[error("OIDC login refused: {0}")]
    Oidc(#[from] OidcDenial),
    #[error("OIDC configuration rejected: {0}")]
    Config(#[from] ConfigError),
    #[error("the client secret reference could not be resolved: {0}")]
    Secret(#[source] io::Error),
    #[error("OIDC URL `{0}` must use https")]
    InsecureUrl(String),
    #[error("OIDC URL is invalid: {0}")]
    InvalidUrl(#[from] openidconnect::url::ParseError),
    #[error("account `{0}` uses the reserved oidc: prefix without being external")]
    ReservedAccount(String),
    #[error("random source failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("password hashing parameters rejected: {0}")]
    Params(#[from] argon2::Error),
    #[error("password hash failed: {0}")]
    Hash(#[from] argon2::password_hash::Error),
    #[error("password policy: {0}")]
    Policy(#[from] PolicyViolation),
    #[error("store key must be exactly 32 bytes")]
    InvalidKey,
    #[error("a secret could not be encrypted")]
    Encrypt,
    #[error("a stored secret could not be decrypted")]
    Decrypt,
    #[error("account store I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("account store is malformed: {0}")]
    Format(#[from] serde_json::Error),
    #[error("account store version {found} is not supported")]
    UnsupportedVersion { found: u32 },
    #[error("key file rejected: {0}")]
    KeyFile(#[source] AuditError),
    #[error("audit failed: {0}")]
    Audit(#[from] AuditError),
    #[error("system clock is before 1970")]
    ClockBeforeEpoch,
    #[error("invalid user name")]
    InvalidUsername,
    #[error("account already exists")]
    AccountExists,
    #[error("the store already holds accounts")]
    AlreadyBootstrapped,
    #[error("no such account")]
    NoSuchAccount,
    #[error("unknown role `{0}`")]
    UnknownRole(String),
    #[error("role `{0}` is built in and cannot be redefined")]
    BuiltInRole(String),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("a second factor is required")]
    MfaRequired,
    #[error("the second factor is invalid")]
    MfaInvalid,
    #[error("this account must enrol a second factor before logging in")]
    MfaEnrolmentRequired,
    #[error("too many failures, locked until {until}")]
    Locked { until: OffsetDateTime },
    #[error("permission denied")]
    PermissionDenied,
    #[error("session is invalid or expired")]
    SessionInvalid,
    #[error("invalid command: {0}")]
    Usage(String),
}
