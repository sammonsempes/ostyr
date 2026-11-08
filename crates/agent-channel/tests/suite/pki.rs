use rcgen::string::Ia5String;
use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};


pub const PRIVATE_MODE: u32 = 0o600;


pub const WORLD_READABLE_MODE: u32 = 0o644;


pub const SERVER_NAME: &str = "localhost";


pub const AGENT_URI: &str = "urn:ostyr:agent:acme:agent-1";


pub const EXPIRED_FROM_YEAR: i32 = 2000;


pub const EXPIRED_TO_YEAR: i32 = 2001;


pub struct Authority {
    pub pem: String,
    pub issuer: Issuer<'static, KeyPair>,
}


pub struct Leaf {
    pub certificate_pem: String,
    pub key_pem: String,
}


pub struct LeafFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}


pub struct LeafSpec {
    pub uris: Vec<String>,
    pub dns: Vec<String>,
    pub expired: bool,
}


pub fn make_authority() -> Result<Authority, Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params.self_signed(&key)?;
    Ok(Authority {
        pem: certificate.pem(),
        issuer: Issuer::new(params, key),
    })
}


pub fn agent_spec(uris: &[&str]) -> LeafSpec {
    LeafSpec {
        uris: uris.iter().map(ToString::to_string).collect(),
        dns: Vec::new(),
        expired: false,
    }
}


pub fn server_spec() -> LeafSpec {
    LeafSpec {
        uris: Vec::new(),
        dns: vec![SERVER_NAME.to_string()],
        expired: false,
    }
}


pub fn issue(authority: &Authority, spec: &LeafSpec) -> Result<Leaf, Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(spec.dns.clone())?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth];
    spec.uris
        .iter()
        .try_for_each(|uri| Ia5String::try_from(uri.as_str()).map(|name| params.subject_alt_names.push(SanType::URI(name))))?;
    if spec.expired {
        params.not_before = date_time_ymd(EXPIRED_FROM_YEAR, 1, 1);
        params.not_after = date_time_ymd(EXPIRED_TO_YEAR, 1, 1);
    }
    let certificate = params.signed_by(&key, &authority.issuer)?;
    Ok(Leaf {
        certificate_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
    })
}


pub fn write_file(dir: &Path, name: &str, content: &str, mode: u32) -> Result<PathBuf, Box<dyn Error>> {
    let path = dir.join(name);
    fs::write(&path, content)?;
    set_mode(&path, mode)?;
    Ok(path)
}


pub fn write_leaf(dir: &Path, name: &str, leaf: &Leaf) -> Result<LeafFiles, Box<dyn Error>> {
    Ok(LeafFiles {
        certificate: write_file(dir, &format!("{name}.crt"), &leaf.certificate_pem, WORLD_READABLE_MODE)?,
        key: write_file(dir, &format!("{name}.key"), &leaf.key_pem, PRIVATE_MODE)?,
    })
}


#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}


#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _mode: u32) -> Result<(), Box<dyn Error>> {
    Ok(())
}


pub fn make_intermediate(root: &Authority) -> Result<Authority, Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params.signed_by(&key, &root.issuer)?;
    Ok(Authority {
        pem: certificate.pem(),
        issuer: Issuer::new(params, key),
    })
}
