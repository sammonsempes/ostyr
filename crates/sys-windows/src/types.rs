use std::path::PathBuf;
use thiserror::Error;


/// One access control entry reduced to what the judge reads: type byte, flag byte, SID string and access mask (deny and unknown types carry no SID).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ace {
    pub kind: u8,
    pub flags: u8,
    pub sid: String,
    pub mask: u32,
}


/// A security descriptor reduced to its owner SID string and its DACL (`None` is a NULL DACL).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedDescriptor {
    pub owner: String,
    pub dacl: Option<Vec<Ace>>,
}


/// The SID strings the agent trusts to hold rights on its directories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principals {
    pub trusted: Vec<String>,
}


/// An absolute local path split into its volume root (`C:\`) and its components, every one checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumePath {
    pub root: String,
    pub components: Vec<String>,
}


/// The identity of an opened file: volume serial number and 64-bit file index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume: u32,
    pub index: u64,
}


#[derive(Debug, Error)]
pub enum DirAclError {
    #[error("{} has a NULL DACL: everyone has full access", .path.display())]
    NullDacl { path: PathBuf },
    #[error("{} has an access control entry of unknown type {kind:#x}", .path.display())]
    UnknownAceType { path: PathBuf, kind: u8 },
    #[error("{} grants {bits:#010x} to {sid}, which is not a trusted principal", .path.display())]
    UntrustedAce { path: PathBuf, sid: String, bits: u32 },
    #[error("{} is owned by {sid}, which is not a trusted principal", .path.display())]
    UntrustedOwner { path: PathBuf, sid: String },
    #[error("{path} is not an absolute local path: {reason}")]
    BadPath { path: String, reason: &'static str },
    #[error("{} is a reparse point (junction, symbolic link or mount point)", .path.display())]
    ReparsePoint { path: PathBuf },
    #[error("{} exists and is not a regular file", .path.display())]
    NotRegularFile { path: PathBuf },
    #[error("{} is not the directory the walk judged", .path.display())]
    IdentityMismatch { path: PathBuf },
    #[error("cannot open {} for the walk: {kind:?}", .path.display())]
    Open { path: PathBuf, kind: std::io::ErrorKind },
    #[error("invalid SID: {0}")]
    InvalidSid(&'static str),
    #[error("malformed security descriptor: {0}")]
    Malformed(&'static str),
    #[error("{operation} failed with code {code:#010x}")]
    Windows { operation: &'static str, code: u32 },
}


/// A pseudo-console size already checked against the bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleSize {
    pub columns: u16,
    pub rows: u16,
}


/// Whether the console of a session is still to be closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseState {
    Open,
    Closed,
}


#[derive(Debug, Error)]
pub enum ConsoleError {
    #[error("console size {columns}x{rows} is outside 1..={max_columns} columns and 1..={max_rows} rows")]
    BadSize {
        columns: u32,
        rows: u32,
        max_columns: u16,
        max_rows: u16,
    },
    #[error("environment variable name is empty or outside [A-Za-z0-9_]")]
    BadEnvironmentName,
    #[error("environment variable {name} has a NUL in its value")]
    BadEnvironmentValue { name: String },
    #[error("environment variable {name} is defined twice")]
    DuplicateEnvironmentName { name: String },
    #[error("directory {0:?} is not an absolute drive path without quote, semicolon or NUL")]
    BadDirectory(String),
    #[error("session label is empty, longer than {max_bytes} bytes, starts with '-' or leaves [A-Za-z0-9._-]")]
    BadSessionLabel { max_bytes: usize },
    #[error("the console is already closed")]
    AlreadyClosed,
    #[error("{operation} failed with code {code:#010x}")]
    Windows { operation: &'static str, code: u32 },
    #[error("{operation} failed: {kind:?}")]
    Io { operation: &'static str, kind: std::io::ErrorKind },
    #[error("{operation} returned no usable directory")]
    DirectoryRead { operation: &'static str },
    #[error("{bytes} input bytes exceed the {max_bytes} byte limit of one write")]
    InputTooLarge { bytes: usize, max_bytes: usize },
    #[error("the shell did not end within {millis} ms of the close")]
    CloseTimeout { millis: u32 },
    #[error("the output drain thread failed during the close")]
    DrainFailed,
    #[error("program {0:?} is not an absolute local path to an .exe without quote or slash")]
    BadProgram(String),
    #[error("argument {index} has a NUL")]
    BadArgument { index: usize },
    #[error("{what}: more than {max} entries")]
    TooMany { what: &'static str, max: usize },
    #[error("another read of the child output is already running")]
    ReaderBusy,
    #[error("{what} is longer than {max_units} UTF-16 units")]
    TooLarge { what: &'static str, max_units: usize },
}


/// The UTF-16, NUL terminated pieces of a job spawn, every one checked: program, command line, environment block and working directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobLaunch {
    pub program: Vec<u16>,
    pub command: Vec<u16>,
    pub environment: Vec<u16>,
    pub directory: Vec<u16>,
}


/// A step run right before the child joins its job: it gets the child's process id and returns a Windows error code to refuse the session.
pub type AssignHook = fn(u32) -> Result<(), u32>;


/// The injected steps of a job spawn: the assignment hook, an action right after `CreateProcessW` and one right after the inherit flags are cleared (tests start a sibling process in them).
#[derive(Clone, Copy)]
pub struct SpawnHooks {
    pub assign: AssignHook,
    pub after_create: fn(),
    pub after_clear: fn(),
}


#[doc = "A file opened by `open_for_verification` (deny-write share mode); the field is crate-private so a plain `File` cannot be passed to the check.\n\n```compile_fail,E0603\nlet file = std::fs::File::open(\"any.exe\").unwrap();\nlet _held = sys_windows::types::VerificationFile(file);\n```\n"]
#[derive(Debug)]
pub struct VerificationFile(pub(crate) std::fs::File);


/// The fields of the PE version resource a caller applies its name and version floor to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionInfo {
    pub original_file_name: Option<String>,
    pub internal_name: Option<String>,
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub file_version: VersionParts,
    pub file_version_text: Option<String>,
}


/// What the judgement of a signed file carries: file SHA-256, version resource, leaf subject and root certificate SHA-256 (lower case hex).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFile {
    pub file_sha256: String,
    pub version: VersionInfo,
    pub leaf_subject: String,
    pub root_sha256: String,
}


/// A good signature chained to a pinned root, or the same with revocation not checkable (offline): the caller decides by policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureOutcome {
    Trusted(SignedFile),
    RevocationUnknown(SignedFile),
}


/// The primary signer facts the pure judgement reads off the two certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerFacts {
    pub leaf_subject: String,
    pub root_sha256: String,
}


/// What `WinVerifyTrust` answered, reduced to the cases the judgement tells apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStatus {
    Valid,
    RevocationUnknown,
    Unsigned,
    Revoked,
    Refused(u32),
}


#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("the file is larger than {max_bytes} bytes")]
    FileTooLarge { max_bytes: u64 },
    #[error("cannot read the file: {kind:?}")]
    Read { kind: std::io::ErrorKind },
    #[error("the file has no readable PE version resource")]
    NoVersionInfo,
    #[error("the file has no embedded Authenticode signature")]
    Unsigned,
    #[error("a certificate of the signer chain is revoked")]
    Revoked,
    #[error("the signature is not trusted: WinVerifyTrust returned {code:#010x}")]
    Untrusted { code: u32 },
    #[error("the signer chain is missing or empty")]
    NoChain,
    #[error("the chain root {root_sha256} is not a pinned Microsoft root")]
    RootNotPinned { root_sha256: String },
    #[error("the signer certificate cannot be parsed")]
    BadCertificate,
    #[error("the signer certificate {field} is not an accepted Microsoft signer name")]
    WrongSubject { field: &'static str },
    #[error("the signer certificate does not allow code signing")]
    NoCodeSigning,
    #[error("the signature check did not answer within {millis} ms")]
    Timeout { millis: u64 },
    #[error("the signature check worker failed")]
    WorkerFailed,
    #[error("{operation} failed with code {code:#010x}")]
    Windows { operation: &'static str, code: u32 },
}


/// The DER encoded leaf and root certificates of the primary signer chain and the error bits of its chain context (`CERT_TRUST_STATUS`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerChain {
    pub leaf_der: Vec<u8>,
    pub root_der: Vec<u8>,
    pub error_status: u32,
}


/// A unit of work run on a worker thread under a deadline.
pub type Work = Box<dyn FnOnce() -> Result<SignatureOutcome, SignatureError> + Send>;


pub const SHA256_BYTES: usize = 32;


pub const VERSION_PART_COUNT: usize = 4;


pub type Sha256Digest = [u8; SHA256_BYTES];


pub type VersionParts = [u16; VERSION_PART_COUNT];
