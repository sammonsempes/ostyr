use script_library::error::ScriptError;
use script_library::model::{Interpreter, Manifest, ParamKind, ParamValue};
use script_library::types::Params;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Read};


pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";


pub const TIMEOUT_SECONDS: u64 = 60;


pub const OUTPUT_CAP: u64 = 1024;


pub fn manifest_with(interpreter: Interpreter, parameters: Vec<(&str, ParamKind)>) -> Manifest {
    Manifest {
        name: "cleanup-logs".to_string(),
        interpreter,
        script: "linux/cleanup.sh".to_string(),
        sha256: EMPTY_SHA256.to_string(),
        timeout_seconds: TIMEOUT_SECONDS,
        max_output_bytes: OUTPUT_CAP,
        parameters: parameters
            .into_iter()
            .map(|(name, kind)| (name.to_string(), kind))
            .collect::<BTreeMap<_, _>>(),
    }
}


pub fn single(name: &str, kind: ParamKind) -> Manifest {
    manifest_with(Interpreter::Bash, vec![(name, kind)])
}


pub fn text_kind(min_length: usize, max_length: usize, pattern: Option<&str>) -> ParamKind {
    ParamKind::Text {
        min_length,
        max_length,
        pattern: pattern.map(str::to_string),
    }
}


pub fn path_kind(prefixes: &[&str]) -> ParamKind {
    ParamKind::Path {
        allowed_prefixes: prefixes.iter().map(|prefix| prefix.to_string()).collect(),
    }
}


pub fn text(value: &str) -> ParamValue {
    ParamValue::Text(value.to_string())
}


pub fn params_of(entries: Vec<(&str, ParamValue)>) -> Params {
    entries.into_iter().map(|(name, value)| (name.to_string(), value)).collect()
}


pub fn refusal<Value>(result: Result<Value, ScriptError>) -> Result<ScriptError, Box<dyn Error>> {
    match result {
        Ok(_) => Err("expected a refusal".into()),
        Err(error) => Ok(error),
    }
}


pub fn refusal_io<Value>(result: io::Result<Value>) -> Result<io::Error, Box<dyn Error>> {
    match result {
        Ok(_) => Err("expected an I/O failure".into()),
        Err(error) => Ok(error),
    }
}


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected read failure"))
    }
}
