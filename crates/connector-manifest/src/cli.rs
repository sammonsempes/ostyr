use crate::error::ConnectorError;
use crate::keys::load_trusted_keys;
use crate::output::write_skeleton;
use crate::skeleton::{skeleton_from_file, summary_line};
use crate::verify::{sign_directory, verify_package};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTimeError};


pub const USAGE: &str = "connector-manifest verify <dir> <keys.yaml> | sign <dir> <key-file> | skeleton <openapi.json> <name> <publisher> <out-dir>";


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
        ["skeleton", openapi, name, publisher, out_directory] => {
            let skeleton = skeleton_from_file(Path::new(openapi), name, publisher)?;
            write_skeleton(Path::new(out_directory), &skeleton)?;
            writeln!(out, "{}", summary_line(&skeleton.summary))?;
            Ok(())
        }
        _ => Err(ConnectorError::Usage(USAGE)),
    }
}
