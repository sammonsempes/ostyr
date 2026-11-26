use crate::pe::{pe_file, spec_with, sysmon_spec};
use crate::types::{GoodPair, OptionalChain, TestResult};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair};
use std::io::Read;
use std::sync::mpsc::{channel, SendError};
use std::time::Duration;
use sys_windows::signer::{
    finish, judge_signer, note_late_answer, read_bounded, revocation_unknown, run_with_deadline, sha256_hex, trust_status, CHAIN_OFFLINE_REVOCATION,
    CHAIN_REVOCATION_STATUS_UNKNOWN, MICROSOFT_ROOTS, MICROSOFT_ROOT_2010_SHA256, MICROSOFT_ROOT_2011_SHA256, SIGNER_COMMON_NAMES,
    SIGNER_ORGANIZATION,
};
use sys_windows::types::{Sha256Digest, SignatureError, SignatureOutcome, SignedFile, SignerChain, TrustStatus, SHA256_BYTES};


const HANG_GUARD: Duration = Duration::from_secs(60);


const SHORT_DEADLINE: Duration = Duration::from_millis(50);


const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";


const ROOT_2010_HEX: &str = "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e";


const ROOT_2011_HEX: &str = "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61";


const MICROSOFT: &str = "Microsoft Corporation";


const PUBLISHER: &str = "Microsoft Windows Publisher";


const ORGANIZATION_OID: [u64; 4] = [2, 5, 4, 10];


const COMMON_NAME_OID: [u64; 4] = [2, 5, 4, 3];


const EKU_OID: [u64; 4] = [2, 5, 29, 37];


const GARBAGE: u8 = 0xFF;


const HRESULT_NO_SIGNATURE: u32 = 0x800B_0100;


const HRESULT_PROVIDER_UNKNOWN: u32 = 0x800B_0001;


const HRESULT_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;


const HRESULT_REVOKED: u32 = 0x800B_010C;


const HRESULT_REVOCATION_FAILURE: u32 = 0x800B_010E;


const HRESULT_REVOCATION_OFFLINE: u32 = 0x8009_2013;


const HRESULT_UNTRUSTED_ROOT: u32 = 0x800B_0109;


const FILE_LIMIT: u64 = 8;


const HEX_PAIR: usize = 2;


const UNRELATED_BIT: u32 = 0x1;


const HEX_RADIX: u32 = 16;


const NOT_A_PE: [u8; 4] = [0; 4];


pub struct Subject {
    pub organizations: Vec<&'static str>,
    pub common_names: Vec<&'static str>,
    pub usages: Vec<ExtendedKeyUsagePurpose>,
    pub garbage_usage: bool,
}


pub fn microsoft_subject() -> Subject {
    Subject {
        organizations: vec![MICROSOFT],
        common_names: vec![PUBLISHER],
        usages: vec![ExtendedKeyUsagePurpose::CodeSigning],
        garbage_usage: false,
    }
}


pub fn certificate(subject: &Subject) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    subject.organizations.iter().enumerate().for_each(|(index, value)| {
        if index == 0 {
            name.push(DnType::OrganizationName, *value);
        } else {
            name.push(DnType::CustomDnType(ORGANIZATION_OID.to_vec()), *value);
        }
    });
    subject.common_names.iter().enumerate().for_each(|(index, value)| {
        if index == 0 {
            name.push(DnType::CommonName, *value);
        } else {
            name.push(DnType::CustomDnType(COMMON_NAME_OID.to_vec()), *value);
        }
    });
    params.distinguished_name = name;
    params.extended_key_usages = subject.usages.clone();
    if subject.garbage_usage {
        params.custom_extensions.push(CustomExtension::from_oid_content(&EKU_OID, vec![GARBAGE]));
    }
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok(certificate.der().to_vec())
}


fn root_pinned(root: &[u8]) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    let digest = sha256_hex(root);
    let mut bytes = [0u8; SHA256_BYTES];
    digest
        .as_bytes()
        .chunks(HEX_PAIR)
        .zip(bytes.iter_mut())
        .try_for_each(|(pair, slot)| -> Result<(), Box<dyn std::error::Error>> {
            *slot = u8::from_str_radix(std::str::from_utf8(pair)?, HEX_RADIX)?;
            Ok(())
        })?;
    Ok(bytes)
}


fn good_pair() -> GoodPair {
    let leaf = certificate(&microsoft_subject())?;
    let root = certificate(&Subject {
        organizations: vec!["Test Root"],
        common_names: vec!["Test Root CA"],
        usages: Vec::new(),
        garbage_usage: false,
    })?;
    let pinned = root_pinned(&root)?;
    Ok((leaf, root, pinned))
}


fn wrong_subject(error: Result<impl std::fmt::Debug, SignatureError>, expected: &str) -> bool {
    matches!(error, Err(SignatureError::WrongSubject { field }) if field == expected)
}


#[test]
fn the_pinned_roots_are_the_two_captured_digests() -> TestResult {
    assert_eq!(sha256_hex(b"abc"), ABC_SHA256);
    assert_eq!(MICROSOFT_ROOTS, [MICROSOFT_ROOT_2010_SHA256, MICROSOFT_ROOT_2011_SHA256]);
    let to_hex = |bytes: Sha256Digest| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    assert_eq!(to_hex(MICROSOFT_ROOT_2010_SHA256), ROOT_2010_HEX);
    assert_eq!(to_hex(MICROSOFT_ROOT_2011_SHA256), ROOT_2011_HEX);
    assert_eq!(SIGNER_ORGANIZATION, MICROSOFT);
    assert_eq!(SIGNER_COMMON_NAMES, [MICROSOFT, PUBLISHER]);
    Ok(())
}


#[test]
fn trust_status_names_every_windows_answer() -> TestResult {
    assert_eq!(trust_status(0), TrustStatus::Valid);
    assert_eq!(trust_status(HRESULT_REVOCATION_FAILURE), TrustStatus::RevocationUnknown);
    assert_eq!(trust_status(HRESULT_REVOCATION_OFFLINE), TrustStatus::RevocationUnknown);
    assert_eq!(trust_status(HRESULT_NO_SIGNATURE), TrustStatus::Unsigned);
    assert_eq!(trust_status(HRESULT_PROVIDER_UNKNOWN), TrustStatus::Unsigned);
    assert_eq!(trust_status(HRESULT_SUBJECT_FORM_UNKNOWN), TrustStatus::Unsigned);
    assert_eq!(trust_status(HRESULT_REVOKED), TrustStatus::Revoked);
    assert_eq!(trust_status(HRESULT_UNTRUSTED_ROOT), TrustStatus::Refused(HRESULT_UNTRUSTED_ROOT));
    Ok(())
}


#[test]
fn a_microsoft_signer_chained_to_a_pinned_root_is_accepted() -> TestResult {
    let (leaf, root, pinned) = good_pair()?;
    let facts = judge_signer(&leaf, &root, &[pinned])?;
    assert_eq!(facts.root_sha256, sha256_hex(&root));
    assert!(facts.leaf_subject.contains(MICROSOFT));
    assert!(facts.leaf_subject.contains(PUBLISHER));
    Ok(())
}


#[test]
fn both_common_names_are_accepted() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.common_names = vec![MICROSOFT];
    judge_signer(&certificate(&subject)?, &root, &[pinned])?;
    Ok(())
}


#[test]
fn a_root_outside_the_pinned_set_is_refused_by_its_digest() -> TestResult {
    let (leaf, root, _) = good_pair()?;
    let result = judge_signer(&leaf, &root, &MICROSOFT_ROOTS);
    assert!(matches!(result, Err(SignatureError::RootNotPinned { root_sha256 }) if root_sha256 == sha256_hex(&root)));
    assert!(matches!(judge_signer(&leaf, &root, &[]), Err(SignatureError::RootNotPinned { .. })));
    Ok(())
}


#[test]
fn another_organization_is_refused() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.organizations = vec!["Evil Corporation"];
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "organization"));
    subject.organizations = vec![PUBLISHER];
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "organization"));
    subject.organizations = Vec::new();
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "organization"));
    Ok(())
}


#[test]
fn a_second_organization_is_refused() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.organizations = vec![MICROSOFT, "Evil Corporation"];
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "organization"));
    Ok(())
}


#[test]
fn another_common_name_is_refused() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.common_names = vec!["Microsoft Corporation (not really)"];
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "common name"));
    subject.common_names = Vec::new();
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "common name"));
    subject.common_names = vec![PUBLISHER, MICROSOFT];
    assert!(wrong_subject(judge_signer(&certificate(&subject)?, &root, &[pinned]), "common name"));
    Ok(())
}


#[test]
fn a_leaf_without_code_signing_is_refused() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.usages = vec![ExtendedKeyUsagePurpose::TimeStamping];
    assert!(matches!(
        judge_signer(&certificate(&subject)?, &root, &[pinned]),
        Err(SignatureError::NoCodeSigning)
    ));
    subject.usages = Vec::new();
    assert!(matches!(
        judge_signer(&certificate(&subject)?, &root, &[pinned]),
        Err(SignatureError::NoCodeSigning)
    ));
    Ok(())
}


#[test]
fn a_leaf_with_an_unreadable_usage_extension_is_refused() -> TestResult {
    let (_, root, pinned) = good_pair()?;
    let mut subject = microsoft_subject();
    subject.usages = Vec::new();
    subject.garbage_usage = true;
    assert!(matches!(
        judge_signer(&certificate(&subject)?, &root, &[pinned]),
        Err(SignatureError::BadCertificate | SignatureError::NoCodeSigning)
    ));
    Ok(())
}


#[test]
fn a_leaf_that_is_not_a_certificate_or_has_trailing_bytes_is_refused() -> TestResult {
    let (leaf, root, pinned) = good_pair()?;
    assert!(matches!(judge_signer(&[GARBAGE], &root, &[pinned]), Err(SignatureError::BadCertificate)));
    let mut padded = leaf;
    padded.push(0);
    assert!(matches!(judge_signer(&padded, &root, &[pinned]), Err(SignatureError::BadCertificate)));
    Ok(())
}


fn chain() -> OptionalChain {
    let (leaf, root, pinned) = good_pair()?;
    Ok((
        Some(SignerChain {
            leaf_der: leaf,
            root_der: root,
            error_status: 0,
        }),
        pinned,
    ))
}


fn file_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pe_file(&sysmon_spec())
}


#[test]
fn a_valid_verification_gives_the_digest_version_subject_and_root() -> TestResult {
    let (pair, pinned) = chain()?;
    let bytes = file_bytes()?;
    let outcome = finish(TrustStatus::Valid, &bytes, pair.clone(), &[pinned])?;
    let SignedFile {
        file_sha256,
        version,
        leaf_subject,
        root_sha256,
    } = match outcome {
        SignatureOutcome::Trusted(signed) => Ok(signed),
        SignatureOutcome::RevocationUnknown(_) => Err("expected Trusted"),
    }?;
    assert_eq!(file_sha256, sha256_hex(&bytes));
    assert_eq!(version.product_name.as_deref(), Some("Sysinternals Sysmon"));
    assert!(leaf_subject.contains(PUBLISHER));
    assert_eq!(root_sha256, sha256_hex(&pair.ok_or("chain")?.root_der));
    Ok(())
}


#[test]
fn a_chain_with_an_unknown_or_offline_revocation_status_is_not_trusted_even_when_windows_says_valid() -> TestResult {
    let (pair, pinned) = chain()?;
    let bytes = file_bytes()?;
    [
        CHAIN_REVOCATION_STATUS_UNKNOWN,
        CHAIN_OFFLINE_REVOCATION,
        CHAIN_REVOCATION_STATUS_UNKNOWN | UNRELATED_BIT,
    ]
    .iter()
    .try_for_each(|bits| -> TestResult {
        let flagged = pair.clone().map(|signer_chain| SignerChain {
            error_status: *bits,
            ..signer_chain
        });
        let outcome = finish(TrustStatus::Valid, &bytes, flagged, &[pinned])?;
        assert!(matches!(outcome, SignatureOutcome::RevocationUnknown(_)), "bits {bits:#x}");
        assert!(revocation_unknown(*bits));
        Ok(())
    })?;
    let clean = pair.map(|signer_chain| SignerChain {
        error_status: UNRELATED_BIT,
        ..signer_chain
    });
    assert!(matches!(
        finish(TrustStatus::Valid, &bytes, clean, &[pinned])?,
        SignatureOutcome::Trusted(_)
    ));
    assert!(!revocation_unknown(UNRELATED_BIT));
    assert!(!revocation_unknown(0));
    Ok(())
}


#[test]
fn an_offline_revocation_check_is_its_own_outcome() -> TestResult {
    let (pair, pinned) = chain()?;
    let outcome = finish(TrustStatus::RevocationUnknown, &file_bytes()?, pair, &[pinned])?;
    assert!(matches!(outcome, SignatureOutcome::RevocationUnknown(_)));
    Ok(())
}


#[test]
fn a_refusing_status_is_its_named_error_and_never_reads_the_chain() -> TestResult {
    let bytes = file_bytes()?;
    assert!(matches!(finish(TrustStatus::Unsigned, &bytes, None, &[]), Err(SignatureError::Unsigned)));
    assert!(matches!(finish(TrustStatus::Revoked, &bytes, None, &[]), Err(SignatureError::Revoked)));
    assert!(matches!(
        finish(TrustStatus::Refused(HRESULT_UNTRUSTED_ROOT), &bytes, None, &[]),
        Err(SignatureError::Untrusted {
            code: HRESULT_UNTRUSTED_ROOT
        })
    ));
    Ok(())
}


#[test]
fn a_good_status_without_a_chain_is_refused() -> TestResult {
    assert!(matches!(
        finish(TrustStatus::Valid, &file_bytes()?, None, &[]),
        Err(SignatureError::NoChain)
    ));
    Ok(())
}


#[test]
fn a_good_signature_over_a_file_without_a_version_resource_is_refused() -> TestResult {
    let (pair, pinned) = chain()?;
    assert!(matches!(
        finish(TrustStatus::Valid, &NOT_A_PE, pair, &[pinned]),
        Err(SignatureError::NoVersionInfo)
    ));
    Ok(())
}


#[test]
fn the_version_resource_without_names_still_gives_a_judgement() -> TestResult {
    let (pair, pinned) = chain()?;
    let bytes = pe_file(&spec_with(&[]))?;
    assert!(finish(TrustStatus::Valid, &bytes, pair, &[pinned]).is_ok());
    Ok(())
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}


#[test]
fn a_file_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() -> TestResult {
    let at_limit = vec![1u8; usize::try_from(FILE_LIMIT)?];
    assert_eq!(read_bounded(&mut at_limit.as_slice(), FILE_LIMIT)?, at_limit);
    let over = vec![1u8; usize::try_from(FILE_LIMIT)? + 1];
    assert!(matches!(
        read_bounded(&mut over.as_slice(), FILE_LIMIT),
        Err(SignatureError::FileTooLarge { max_bytes: FILE_LIMIT })
    ));
    Ok(())
}


#[test]
fn a_read_error_keeps_only_its_kind() -> TestResult {
    assert!(matches!(
        read_bounded(&mut Failing, FILE_LIMIT),
        Err(SignatureError::Read {
            kind: std::io::ErrorKind::PermissionDenied
        })
    ));
    Ok(())
}


fn outcome_for_tests() -> Result<SignatureOutcome, SignatureError> {
    finish(TrustStatus::Unsigned, &[], None, &[])
}


#[test]
fn the_worker_answer_comes_back_before_the_deadline() -> TestResult {
    let result = run_with_deadline(HANG_GUARD, Box::new(outcome_for_tests));
    assert!(matches!(result, Err(SignatureError::Unsigned)));
    Ok(())
}


#[test]
fn a_worker_that_does_not_answer_is_a_timeout_and_its_late_answer_is_dropped() -> TestResult {
    let (release, wait) = channel::<()>();
    let result = run_with_deadline(
        SHORT_DEADLINE,
        Box::new(move || {
            wait.recv_timeout(HANG_GUARD).map_err(|_| SignatureError::WorkerFailed)?;
            outcome_for_tests()
        }),
    );
    assert!(matches!(result, Err(SignatureError::Timeout { millis }) if millis == u64::try_from(SHORT_DEADLINE.as_millis()).unwrap_or(0)));
    release.send(())?;
    Ok(())
}


#[test]
fn a_worker_that_dies_is_a_worker_failure() -> TestResult {
    let result = run_with_deadline(HANG_GUARD, Box::new(|| std::panic::resume_unwind(Box::new("worker died"))));
    assert!(matches!(result, Err(SignatureError::WorkerFailed)));
    Ok(())
}


#[test]
fn a_late_answer_is_logged_not_an_error() -> TestResult {
    note_late_answer(Ok(()));
    note_late_answer(Err(SendError(outcome_for_tests())));
    Ok(())
}
