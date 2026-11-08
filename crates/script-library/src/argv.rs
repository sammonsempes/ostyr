use crate::error::ScriptError;
use crate::model::{Argv, Interpreter, Manifest, ParamValue};
use crate::params::validate_params;
use crate::types::Params;


pub const POWERSHELL_PROGRAM: &str = "pwsh";


pub const BASH_PROGRAM: &str = "bash";


pub const PYTHON_PROGRAM: &str = "python3";


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
        Interpreter::Bash | Interpreter::Python => vec![script.to_string()],
    }
}


fn value_text(value: &ParamValue) -> String {
    match value {
        ParamValue::Text(text) => text.clone(),
        ParamValue::Integer(number) => number.to_string(),
    }
}


/// One element per parameter, name and value joined in the same element (`-name:value`, `--name=value`) so a value starting with `-` is never an option.
fn parameter_arg(interpreter: Interpreter, name: &str, value: &ParamValue) -> String {
    match interpreter {
        Interpreter::Powershell => format!("-{name}:{}", value_text(value)),
        Interpreter::Bash | Interpreter::Python => format!("--{name}={}", value_text(value)),
    }
}


/// Validates the parameters, then returns the interpreter and separate arguments; nothing is ever joined into a shell string.
pub fn build_argv(manifest: &Manifest, params: &Params) -> Result<Argv, ScriptError> {
    validate_params(manifest, params)?;
    let mut args = launch_args(manifest.interpreter, &manifest.script);
    args.extend(params.iter().map(|(name, value)| parameter_arg(manifest.interpreter, name, value)));
    Ok(Argv {
        program: program_of(manifest.interpreter).to_string(),
        args,
    })
}
