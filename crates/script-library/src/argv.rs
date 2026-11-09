use crate::check::check_manifest;
use crate::error::ScriptError;
use crate::model::{Argv, Interpreter, Manifest, ParamValue};
use crate::params::validate_params;
use crate::types::Params;


pub const POWERSHELL_PROGRAM: &str = "pwsh";


pub const BASH_PROGRAM: &str = "bash";


pub const PYTHON_PROGRAM: &str = "python3";


pub const PYTHON_OPTION: &str = "-I";


pub const POWERSHELL_OPTIONS: [&str; 3] = ["-NoProfile", "-NonInteractive", "-File"];


fn program_of(interpreter: Interpreter) -> &'static str {
    match interpreter {
        Interpreter::Powershell => POWERSHELL_PROGRAM,
        Interpreter::Bash => BASH_PROGRAM,
        Interpreter::Python => PYTHON_PROGRAM,
    }
}


fn launch_args(interpreter: Interpreter, script: &str) -> Vec<String> {
    match interpreter {
        Interpreter::Powershell => POWERSHELL_OPTIONS
            .iter()
            .map(|option| option.to_string())
            .chain([script.to_string()])
            .collect(),
        Interpreter::Bash => vec![script.to_string()],
        Interpreter::Python => vec![PYTHON_OPTION.to_string(), script.to_string()],
    }
}


fn value_text(value: &ParamValue) -> String {
    match value {
        ParamValue::Text(text) => text.clone(),
        ParamValue::Integer(number) => number.to_string(),
    }
}


/// One element per parameter, name and value in the same element (`-name:value`, `--name=value`): never read as an option.
fn parameter_arg(interpreter: Interpreter, name: &str, value: &ParamValue) -> String {
    match interpreter {
        Interpreter::Powershell => format!("-{name}:{}", value_text(value)),
        Interpreter::Bash | Interpreter::Python => format!("--{name}={}", value_text(value)),
    }
}


/// Interpreter and separate arguments for `script`, without validating anything; the caller has checked manifest and parameters.
pub fn argv_with_script(manifest: &Manifest, params: &Params, script: &str) -> Argv {
    let mut args = launch_args(manifest.interpreter, script);
    args.extend(params.iter().map(|(name, value)| parameter_arg(manifest.interpreter, name, value)));
    Argv {
        program: program_of(manifest.interpreter).to_string(),
        args,
    }
}


/// Checks the manifest and the parameters, then returns the interpreter and separate arguments; nothing is joined into a shell string.
pub fn build_argv(manifest: &Manifest, params: &Params) -> Result<Argv, ScriptError> {
    check_manifest(manifest)?;
    validate_params(manifest, params)?;
    Ok(argv_with_script(manifest, params, &manifest.script))
}
