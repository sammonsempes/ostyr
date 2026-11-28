use crate::pe_version::{parse_version, MAX_FILE_BYTES};
use crate::types::{Sha256Digest, SignatureError, SignatureOutcome, SignedFile, SignerChain, SignerFacts, TrustStatus, VerificationFile, Work};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError, SendError};
use std::time::Duration;
use x509_parser::prelude::{FromDer, X509Certificate};


/// SHA-256 of the encoded Microsoft Root Certificate Authority 2010: the root of the real Sysmon64.exe chain (read live, T936A).
pub const MICROSOFT_ROOT_2010_SHA256: Sha256Digest = [
    0xdf, 0x54, 0x5b, 0xf9, 0x19, 0xa2, 0x43, 0x9c, 0x36, 0x98, 0x3b, 0x54, 0xcd, 0xfc, 0x90, 0x3d, 0xfa, 0x4f, 0x37, 0xd3, 0x99, 0x6d, 0x8d, 0x84,
    0xb4, 0xc3, 0x1e, 0xec, 0x6f, 0x3c, 0x16, 0x3e,
];


/// SHA-256 of the encoded Microsoft Root Certificate Authority 2011 (read from the lab VM's Root store, T936A).
pub const MICROSOFT_ROOT_2011_SHA256: Sha256Digest = [
    0x84, 0x7d, 0xf6, 0xa7, 0x84, 0x97, 0x94, 0x3f, 0x27, 0xfc, 0x72, 0xeb, 0x93, 0xf9, 0xa6, 0x37, 0x32, 0x0a, 0x02, 0xb5, 0x61, 0xd0, 0xa9, 0x1b,
    0x09, 0xe8, 0x7a, 0x78, 0x07, 0xed, 0x7c, 0x61,
];


/// The pinned roots a signer chain may end in.
pub const MICROSOFT_ROOTS: [Sha256Digest; 2] = [MICROSOFT_ROOT_2010_SHA256, MICROSOFT_ROOT_2011_SHA256];


/// The exact value of the leaf subject organisation.
pub const SIGNER_ORGANIZATION: &str = "Microsoft Corporation";


/// The leaf subject common names accepted with that organisation: the Sysmon 15.22 leaf is `Microsoft Windows Publisher`.
pub const SIGNER_COMMON_NAMES: [&str; 2] = ["Microsoft Corporation", "Microsoft Windows Publisher"];


const HRESULT_NO_SIGNATURE: u32 = 0x800B_0100;


const HRESULT_PROVIDER_UNKNOWN: u32 = 0x800B_0001;


const HRESULT_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;


const HRESULT_REVOKED: u32 = 0x800B_010C;


const HRESULT_REVOCATION_FAILURE: u32 = 0x800B_010E;


const HRESULT_REVOCATION_OFFLINE: u32 = 0x8009_2013;


/// `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`: a certificate of the chain has no revocation answer.
pub const CHAIN_REVOCATION_STATUS_UNKNOWN: u32 = 0x40;


/// `CERT_TRUST_IS_REVOKED`: a certificate of the chain is revoked.
pub const CHAIN_IS_REVOKED: u32 = 0x4;


/// `CERT_TRUST_IS_OFFLINE_REVOCATION`: the revocation server could not be reached.
pub const CHAIN_OFFLINE_REVOCATION: u32 = 0x0100_0000;


/// WinVerifyTrust soft-fails an unreachable revocation server (it answers 0), so the chain context error bits decide whether revocation was really checked.
pub fn revocation_unknown(error_status: u32) -> bool {
    error_status & (CHAIN_REVOCATION_STATUS_UNKNOWN | CHAIN_OFFLINE_REVOCATION) != 0
}


/// Lower case hex of the SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}


/// Maps a `WinVerifyTrust` result: 0 is valid, the two offline revocation codes are their own outcome, a missing signature and a revoked certificate are named.
pub fn trust_status(code: u32) -> TrustStatus {
    match code {
        0 => TrustStatus::Valid,
        HRESULT_REVOCATION_FAILURE | HRESULT_REVOCATION_OFFLINE => TrustStatus::RevocationUnknown,
        HRESULT_NO_SIGNATURE | HRESULT_PROVIDER_UNKNOWN | HRESULT_SUBJECT_FORM_UNKNOWN => TrustStatus::Unsigned,
        HRESULT_REVOKED => TrustStatus::Revoked,
        other => TrustStatus::Refused(other),
    }
}


fn exactly_one_of<'a>(mut values: impl Iterator<Item = Option<&'a str>>, allowed: &[&str], field: &'static str) -> Result<(), SignatureError> {
    let first = values.next().flatten();
    let extra = values.next();
    first
        .is_some_and(|value| allowed.contains(&value))
        .then_some(())
        .filter(|()| extra.is_none())
        .ok_or(SignatureError::WrongSubject { field })
}


/// Judges the primary signer chain from its leaf and root certificates (DER): the root digest is in `pinned`, the leaf subject has exactly one O `Microsoft Corporation` and one CN from `SIGNER_COMMON_NAMES` and the leaf allows code signing.
pub fn judge_signer(leaf_der: &[u8], root_der: &[u8], pinned: &[Sha256Digest]) -> Result<SignerFacts, SignatureError> {
    let root_digest: Sha256Digest = Sha256::digest(root_der).into();
    let root_sha256 = sha256_hex(root_der);
    pinned.contains(&root_digest).then_some(()).ok_or_else(|| SignatureError::RootNotPinned {
        root_sha256: root_sha256.clone(),
    })?;
    let (rest, leaf) = X509Certificate::from_der(leaf_der).map_err(|_| SignatureError::BadCertificate)?;
    rest.is_empty().then_some(()).ok_or(SignatureError::BadCertificate)?;
    let subject = leaf.subject();
    exactly_one_of(
        subject.iter_organization().map(|attribute| attribute.as_str().ok()),
        &[SIGNER_ORGANIZATION],
        "organization",
    )?;
    exactly_one_of(
        subject.iter_common_name().map(|attribute| attribute.as_str().ok()),
        &SIGNER_COMMON_NAMES,
        "common name",
    )?;
    let usage = leaf.extended_key_usage().map_err(|_| SignatureError::BadCertificate)?;
    usage
        .is_some_and(|extension| extension.value.code_signing)
        .then_some(())
        .ok_or(SignatureError::NoCodeSigning)?;
    Ok(SignerFacts {
        leaf_subject: subject.to_string(),
        root_sha256,
    })
}


/// Judges a finished verification: a refusing status is its named error; otherwise the chain, the signer and the version read from `bytes` give the result.
pub fn finish(status: TrustStatus, bytes: &[u8], chain: Option<SignerChain>, pinned: &[Sha256Digest]) -> Result<SignatureOutcome, SignatureError> {
    match status {
        TrustStatus::Unsigned => Err(SignatureError::Unsigned),
        TrustStatus::Revoked => Err(SignatureError::Revoked),
        TrustStatus::Refused(code) => Err(SignatureError::Untrusted { code }),
        TrustStatus::Valid | TrustStatus::RevocationUnknown => {
            let signer_chain = chain.ok_or(SignatureError::NoChain)?;
            (signer_chain.error_status & CHAIN_IS_REVOKED == 0)
                .then_some(())
                .ok_or(SignatureError::Revoked)?;
            let facts = judge_signer(&signer_chain.leaf_der, &signer_chain.root_der, pinned)?;
            let unknown = status == TrustStatus::RevocationUnknown || revocation_unknown(signer_chain.error_status);
            let signed = SignedFile {
                file_sha256: sha256_hex(bytes),
                version: parse_version(bytes)?,
                leaf_subject: facts.leaf_subject,
                root_sha256: facts.root_sha256,
            };
            Ok(if unknown {
                SignatureOutcome::RevocationUnknown(signed)
            } else {
                SignatureOutcome::Trusted(signed)
            })
        }
    }
}


/// Reads at most `max_bytes` from `reader`; one byte more is `FileTooLarge`, never a truncated read.
pub fn read_bounded(reader: &mut dyn Read, max_bytes: u64) -> Result<Vec<u8>, SignatureError> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| SignatureError::Read { kind: error.kind() })?;
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    (length <= max_bytes).then_some(bytes).ok_or(SignatureError::FileTooLarge { max_bytes })
}


/// A failed send means the deadline already answered `Timeout` and dropped the receiver: logged, not an error.
pub fn note_late_answer(sent: Result<(), SendError<Result<SignatureOutcome, SignatureError>>>) {
    let late = sent.is_err();
    tracing::debug!(late, "signature check answered after its deadline");
}


/// Runs `work` on its own thread and waits at most `deadline`; a late worker is left to finish alone and the answer is `Timeout`.
pub fn run_with_deadline(deadline: Duration, work: Work) -> Result<SignatureOutcome, SignatureError> {
    let (sender, receiver) = channel();
    let millis = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
    std::thread::spawn(move || note_late_answer(sender.send(work())));
    receiver.recv_timeout(deadline).map_err(|error| match error {
        RecvTimeoutError::Timeout => SignatureError::Timeout { millis },
        RecvTimeoutError::Disconnected => SignatureError::WorkerFailed,
    })?
}


/// `FILE_SHARE_READ`: no other open may write or delete the file while the handle lives.
pub const SHARE_READ_ONLY: u32 = 0x1;


#[cfg(windows)]
pub fn restrict_sharing(options: &mut OpenOptions) -> &mut OpenOptions {
    use std::os::windows::fs::OpenOptionsExt;
    options.share_mode(SHARE_READ_ONLY)
}


#[cfg(not(windows))]
pub fn restrict_sharing(options: &mut OpenOptions) -> &mut OpenOptions {
    options
}


/// Opens `path` for reading with a share mode that denies every writer and deleter until the handle closes: a changed file is a refused open, never other bytes.
pub fn open_for_verification(path: &Path) -> Result<VerificationFile, SignatureError> {
    restrict_sharing(OpenOptions::new().read(true))
        .open(path)
        .map(VerificationFile)
        .map_err(|error| SignatureError::Read { kind: error.kind() })
}


/// Moves the read position of a shared handle back to the start.
pub fn rewind(seekable: &mut dyn Seek) -> Result<(), SignatureError> {
    seekable
        .seek(SeekFrom::Start(0))
        .map(drop)
        .map_err(|error| SignatureError::Read { kind: error.kind() })
}


/// Reads the whole held file (bounded to `MAX_FILE_BYTES`) from a fresh position and leaves the position at the start.
pub fn read_whole(file: &VerificationFile) -> Result<Vec<u8>, SignatureError> {
    rewind(&mut &file.0)?;
    let mut reader = &file.0;
    let bytes = read_bounded(&mut reader, MAX_FILE_BYTES)?;
    rewind(&mut &file.0)?;
    Ok(bytes)
}
