use crate::error::ConnectorError;
use crate::keys::load_trusted_keys;
use crate::verify::{sign_directory, verify_package};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTimeError};


pub const USAGE: &str = "connector-manifest verify <dir> <trusted-keys.yaml> | connector-manifest sign <dir> <key-file>";


/// A clock before the epoch is refused: reading it as 0 would make every key look current.
pub fn epoch_seconds(elapsed: Result<Duration, SystemTimeError>) -> Result<u64, ConnectorError> {
    elapsed.map(|duration| duration.as_secs()).map_err(|_| ConnectorError::Clock)
}


/// `verify <dir> <keys>` or `sign <dir> <key-file>`; one result line on `out`.
pub fn run(args: &[&str], now: u64, out: &mut dyn Write) -> Result<(), ConnectorError> {
    match args {
        ["verify", directory, keys_file] => {
            let verified = verify_package(Path::new(directory), &load_trusted_keys(Path::new(keys_file))?, now)?;
            writeln!(
                out,
                "verified {} {} publisher={} files={}",
                verified.manifest.name,
                verified.manifest.version,
                verified.manifest.publisher,
                verified.files.len()
            )?;
            Ok(())
        }
        ["sign", directory, key_file] => {
            let files = sign_directory(Path::new(directory), Path::new(key_file))?;
            writeln!(out, "signed {directory} files={files}")?;
            Ok(())
        }
        _ => Err(ConnectorError::Usage(USAGE)),
    }
}
