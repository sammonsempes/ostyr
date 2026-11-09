use crate::common::{manifest_with, params_of, refusal, text, text_kind};
use crate::types::TestResult;
use script_library::argv::build_argv;
use script_library::error::ScriptError;
use script_library::model::{Interpreter, Manifest, ParamKind, ParamValue};


const HOSTILE: &str = "x; rm -rf / $(id) `id` | cat && \"q\" 'a' -rf --flag";


pub const BOUND: i64 = 10;


pub const NEGATIVE: i64 = -3;


pub const POSITIVE: i64 = 4;


pub const WIDE: usize = 128;


pub const ARGV_LENGTH: usize = 3;


fn parameters() -> Vec<(&'static str, ParamKind)> {
    vec![
        ("count", ParamKind::Integer { min: -BOUND, max: BOUND }),
        ("label", text_kind(0, WIDE, None)),
    ]
}


#[test]
fn bash_and_python_take_the_script_path_then_joined_arguments() -> TestResult {
    let values = params_of(vec![("label", text(HOSTILE)), ("count", ParamValue::Integer(NEGATIVE))]);
    let bash = build_argv(&manifest_with(Interpreter::Bash, parameters()), &values)?;
    assert_eq!(bash.program, "bash");
    assert_eq!(
        bash.args,
        vec![
            "linux/cleanup.sh".to_string(),
            format!("--count={NEGATIVE}").to_string(),
            format!("--label={HOSTILE}")
        ]
    );
    let python = build_argv(&manifest_with(Interpreter::Python, parameters()), &values)?;
    assert_eq!(python.program, "python3");
    assert_eq!(python.args.first().map(String::as_str), Some("-I"));
    assert_eq!(python.args.get(1).map(String::as_str), Some("linux/cleanup.sh"));
    assert_eq!(python.args.len(), ARGV_LENGTH + 1);
    Ok(())
}


#[test]
fn powershell_uses_file_and_attached_values() -> TestResult {
    let values = params_of(vec![("label", text("-Command")), ("count", ParamValue::Integer(POSITIVE))]);
    let argv = build_argv(&manifest_with(Interpreter::Powershell, parameters()), &values)?;
    assert_eq!(argv.program, "pwsh");
    assert_eq!(
        argv.args,
        vec![
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "linux/cleanup.sh",
            "-count:4",
            "-label:-Command"
        ]
    );
    Ok(())
}


#[test]
fn invalid_parameters_build_nothing() -> TestResult {
    let values = params_of(vec![("label", text("x")), ("count", ParamValue::Integer(BOUND + 1))]);
    let error = refusal(build_argv(&manifest_with(Interpreter::Bash, parameters()), &values))?;
    assert!(matches!(error, ScriptError::OutOfRange(_)));
    Ok(())
}


#[test]
fn manifest_built_in_code_is_checked_too() -> TestResult {
    let hostile = Manifest {
        script: "-c".to_string(),
        ..manifest_with(Interpreter::Bash, vec![])
    };
    let error = refusal(build_argv(&hostile, &params_of(vec![])))?;
    assert!(matches!(error, ScriptError::InvalidManifest { field } if field == "script"));
    Ok(())
}
