use crate::error::CertError;
use crate::model::{CertRecord, KeyType, ParseOutcome};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;
use x509_parser::public_key::PublicKey;


pub const MAX_INPUT_BYTES: usize = 1 << 20;


pub const MAX_PEM_BLOCKS: usize = 64;


pub const MAX_CERTIFICATES: usize = 32;


pub const MAX_DNS_NAMES: usize = 100;


const PEM_START: &[u8] = b"-----BEGIN";


const CERTIFICATE_LABEL: &str = "CERTIFICATE";


const PRIVATE_KEY_SUFFIX: &str = "PRIVATE KEY";


/// Parses a PEM bundle or one DER certificate; PEM private key blocks are counted and dropped unread.
pub fn parse_input(input: &[u8]) -> Result<ParseOutcome, CertError> {
    if input.len() > MAX_INPUT_BYTES {
        Err(CertError::InputTooLarge {
            size: input.len(),
            max: MAX_INPUT_BYTES,
        })
    } else if input.trim_ascii_start().starts_with(PEM_START) {
        parse_pem(input)
    } else {
        Ok(ParseOutcome {
            records: vec![record_from_der(input)?],
            private_keys_refused: 0,
        })
    }
}


pub fn parse_pem(input: &[u8]) -> Result<ParseOutcome, CertError> {
    let blocks = Pem::iter_from_buffer(input)
        .take(MAX_PEM_BLOCKS + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CertError::Pem)?;
    if blocks.len() > MAX_PEM_BLOCKS {
        Err(CertError::TooManyBlocks { max: MAX_PEM_BLOCKS })
    } else {
        let certificates = blocks
            .iter()
            .filter(|block| block.label == CERTIFICATE_LABEL)
            .map(|block| record_from_der(&block.contents))
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.len() > MAX_CERTIFICATES {
            Err(CertError::TooManyCertificates { max: MAX_CERTIFICATES })
        } else {
            Ok(ParseOutcome {
                records: certificates,
                private_keys_refused: blocks.iter().filter(|block| block.label.ends_with(PRIVATE_KEY_SUFFIX)).count(),
            })
        }
    }
}


pub fn record_from_der(der: &[u8]) -> Result<CertRecord, CertError> {
    let (_, certificate) = parse_x509_certificate(der).map_err(CertError::Certificate)?;
    let (key_type, key_bits) = key_of(&certificate);
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    Ok(CertRecord {
        fingerprint_sha256: HEXLOWER.encode(&Sha256::digest(certificate.as_ref())),
        self_signed: subject == issuer,
        subject,
        issuer,
        dns_names: dns_names(&certificate)?,
        not_before: certificate.validity().not_before.timestamp(),
        not_after: certificate.validity().not_after.timestamp(),
        key_type,
        key_bits,
    })
}


fn key_of(certificate: &X509Certificate<'_>) -> (KeyType, Option<usize>) {
    match certificate.public_key().parsed() {
        Ok(key @ PublicKey::RSA(_)) => (KeyType::Rsa, Some(key.key_size())),
        Ok(key @ PublicKey::EC(_)) => (KeyType::Ec, Some(key.key_size())),
        _ => (KeyType::Other, None),
    }
}


fn dns_names(certificate: &X509Certificate<'_>) -> Result<Vec<String>, CertError> {
    let extension = certificate.subject_alternative_name().map_err(CertError::Extension)?;
    Ok(extension.map_or_else(Vec::new, |san| {
        san.value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some((*dns).to_string()),
                _ => None,
            })
            .take(MAX_DNS_NAMES)
            .collect()
    }))
}
