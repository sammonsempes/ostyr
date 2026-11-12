use software_catalog::model::{Available, Catalogue, Entry, Installed, InstalledRow, Manager, Source, Version};
use std::io::Read;


pub mod types;


pub use types::TestResult;


pub const FINGERPRINT: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678";


pub const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected failure"))
    }
}


pub fn entry(name: &str, source: Source, version: &str) -> Entry {
    let publisher = match source {
        Source::Apt(_) | Source::Dnf(_) => FINGERPRINT,
        Source::Winget(_) | Source::Msi(_) => "CN=Example Publisher, O=Example",
    };
    Entry {
        name: name.to_string(),
        source,
        version: Version::Pinned(version.to_string()),
        sha256: None,
        publisher: publisher.to_string(),
        uninstall: false,
    }
}


pub fn apt_entry(name: &str, package: &str, version: &str) -> Entry {
    entry(name, Source::Apt(package.to_string()), version)
}


pub fn catalogue(entries: Vec<Entry>) -> Catalogue {
    Catalogue { entries }
}


pub fn row(manager: Manager, package: &str, version: &str) -> InstalledRow {
    InstalledRow {
        manager,
        package: package.to_string(),
        version: version.to_string(),
        held: false,
    }
}


pub fn available(manager: Manager, names: &[&str]) -> Available {
    Available {
        names: names.iter().map(|name| (manager, name.to_string())).collect(),
        malformed: 0,
        over_limit: 0,
    }
}


pub fn installed(rows: Vec<InstalledRow>) -> Installed {
    Installed {
        rows,
        malformed: 0,
        over_limit: 0,
        not_installed: 0,
    }
}
