use crate::common::{refusal, FailingReader, EMPTY_SHA256};
use crate::types::TestResult;
use script_library::error::ScriptError;
use script_library::load::{load_manifest, read_manifest};
use script_library::model::{
    Interpreter, ParamKind, MAX_ENUM_VALUES, MAX_MANIFEST_BYTES, MAX_NAME_LENGTH, MAX_PARAMETERS, MAX_PATH_LENGTH, MAX_PATTERN_LENGTH, MAX_PREFIXES,
    MAX_STRING_LENGTH,
};


pub const PARAMETER_COUNT: usize = 4;


pub const LABEL_MAX: usize = 8;


pub const FRAME: usize = 2;


fn document(extra: &str) -> String {
    format!(
        "name: cleanup-logs\ninterpreter: bash\nscript: linux/cleanup.sh\nsha256: {EMPTY_SHA256}\ntimeout_seconds: 60\nmax_output_bytes: 1024\n{extra}"
    )
}


#[test]
fn full_manifest_is_parsed() -> TestResult {
    let text = document(
        "parameters:\n  label:\n    type: string\n    max_length: 8\n    pattern: '[a-z]+'\n  days:\n    type: integer\n    min: 1\n    max: 9\n  level:\n    type: enum\n    values: [low, high]\n  target:\n    type: path\n    allowed_prefixes: [/var/log]\n",
    );
    let manifest = read_manifest(text.as_bytes(), "m.yaml")?;
    assert_eq!(manifest.interpreter, Interpreter::Bash);
    assert_eq!(manifest.parameters.len(), PARAMETER_COUNT);
    assert!(matches!(
        manifest.parameters.get("label"),
        Some(ParamKind::Text {
            min_length: 0,
            max_length: LABEL_MAX,
            ..
        })
    ));
    Ok(())
}


#[test]
fn interpreters_parse() -> TestResult {
    let powershell = document("").replace("interpreter: bash", "interpreter: powershell");
    assert_eq!(read_manifest(powershell.as_bytes(), "m.yaml")?.interpreter, Interpreter::Powershell);
    let python = document("").replace("interpreter: bash", "interpreter: python");
    assert_eq!(read_manifest(python.as_bytes(), "m.yaml")?.interpreter, Interpreter::Python);
    Ok(())
}


#[test]
fn unknown_interpreter_is_refused() -> TestResult {
    let text = document("").replace("interpreter: bash", "interpreter: perl");
    let error = refusal(read_manifest(text.as_bytes(), "m.yaml"))?;
    assert!(matches!(error, ScriptError::Config(_)));
    Ok(())
}


#[test]
fn unknown_fields_and_types_are_refused() -> TestResult {
    let field = document("surprise: 1\n");
    assert!(matches!(refusal(read_manifest(field.as_bytes(), "m.yaml"))?, ScriptError::Config(_)));
    let kind = document("parameters:\n  a:\n    type: float\n");
    assert!(matches!(refusal(read_manifest(kind.as_bytes(), "m.yaml"))?, ScriptError::Config(_)));
    let inner = document("parameters:\n  a:\n    type: integer\n    min: 1\n    max: 2\n    step: 1\n");
    assert!(matches!(refusal(read_manifest(inner.as_bytes(), "m.yaml"))?, ScriptError::Config(_)));
    Ok(())
}


fn invalid_field(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    match refusal(read_manifest(text.as_bytes(), "m.yaml"))? {
        ScriptError::InvalidManifest { field } => Ok(field),
        other => Err(format!("unexpected {other}").into()),
    }
}


#[test]
fn top_level_bounds() -> TestResult {
    let cases = [
        (document("").replace("cleanup-logs", "Bad Name"), "name"),
        (document("").replace("cleanup-logs", "''"), "name"),
        (document("").replace("linux/cleanup.sh", "../x.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "/etc/x.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "-x.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "a//b.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "a\\\\b.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "a/./b.sh"), "script"),
        (document("").replace("linux/cleanup.sh", "\"a\\u0001b.sh\""), "script"),
        (document("").replace("linux/cleanup.sh", "''"), "script"),
        (document("").replace("linux/cleanup.sh", &"a".repeat(MAX_PATH_LENGTH + 1)), "script"),
        (document("").replace(EMPTY_SHA256, "ABC"), "sha256"),
        (
            document("").replace(EMPTY_SHA256, &"g".repeat(script_library::model::SHA256_HEX_LENGTH)),
            "sha256",
        ),
        (document("").replace("timeout_seconds: 60", "timeout_seconds: 0"), "timeout_seconds"),
        (document("").replace("timeout_seconds: 60", "timeout_seconds: 86401"), "timeout_seconds"),
        (document("").replace("max_output_bytes: 1024", "max_output_bytes: 0"), "max_output_bytes"),
        (
            document("").replace("max_output_bytes: 1024", "max_output_bytes: 16777217"),
            "max_output_bytes",
        ),
        (document("").replace("cleanup-logs", &format!("a{}", "b".repeat(MAX_NAME_LENGTH))), "name"),
    ];
    cases.iter().try_for_each(|(text, field)| -> TestResult {
        assert_eq!(invalid_field(text)?, *field, "{text}");
        Ok(())
    })?;
    let at_limit = document("")
        .replace("timeout_seconds: 60", "timeout_seconds: 86400")
        .replace("max_output_bytes: 1024", "max_output_bytes: 16777216");
    read_manifest(at_limit.as_bytes(), "m.yaml")?;
    Ok(())
}


fn with_parameter(body: &str) -> String {
    document(&format!("parameters:\n  p:\n{body}"))
}


#[test]
fn parameter_schema_bounds() -> TestResult {
    let long_values = format!("[{}]", vec!["'a'"; MAX_ENUM_VALUES + 1].join(","));
    let long_prefixes = format!("[{}]", vec!["/a"; MAX_PREFIXES + 1].join(","));
    let cases = [
        with_parameter("    type: string\n    min_length: 5\n    max_length: 4\n"),
        with_parameter("    type: string\n    max_length: 4097\n"),
        with_parameter("    type: integer\n    min: 2\n    max: 1\n"),
        with_parameter("    type: enum\n    values: []\n"),
        with_parameter(&format!("    type: enum\n    values: {long_values}\n")),
        with_parameter("    type: enum\n    values: [\"a\\u0000b\"]\n"),
        with_parameter(&format!("    type: enum\n    values: ['{}']\n", "a".repeat(MAX_STRING_LENGTH + 1))),
        with_parameter("    type: path\n    allowed_prefixes: []\n"),
        with_parameter(&format!("    type: path\n    allowed_prefixes: {long_prefixes}\n")),
        with_parameter("    type: path\n    allowed_prefixes: [relative]\n"),
        with_parameter("    type: path\n    allowed_prefixes: ['/a/../b']\n"),
        document("parameters:\n  Bad:\n    type: integer\n    min: 1\n    max: 2\n"),
    ];
    cases.iter().try_for_each(|text| -> TestResult {
        assert!(invalid_field(text)?.starts_with("parameters"), "{text}");
        Ok(())
    })?;
    let at_limits = [
        with_parameter("    type: string\n    min_length: 4096\n    max_length: 4096\n"),
        with_parameter("    type: integer\n    min: 1\n    max: 1\n"),
    ];
    at_limits
        .iter()
        .try_for_each(|text| -> TestResult { read_manifest(text.as_bytes(), "m.yaml").map(drop).map_err(Into::into) })?;
    Ok(())
}


#[test]
fn pattern_bounds() -> TestResult {
    let unbalanced = with_parameter("    type: string\n    max_length: 4\n    pattern: 'a)|(b'\n");
    assert!(matches!(
        refusal(read_manifest(unbalanced.as_bytes(), "m.yaml"))?,
        ScriptError::Pattern(_)
    ));
    let long = with_parameter(&format!(
        "    type: string\n    max_length: 4\n    pattern: '{}'\n",
        "a".repeat(MAX_PATTERN_LENGTH + 1)
    ));
    assert_eq!(invalid_field(&long)?, "pattern");
    let huge = with_parameter("    type: string\n    max_length: 4\n    pattern: '(a{100}){100}'\n");
    assert!(matches!(refusal(read_manifest(huge.as_bytes(), "m.yaml"))?, ScriptError::Pattern(_)));
    Ok(())
}


#[test]
fn too_many_parameters() -> TestResult {
    let entries: String = (0..=MAX_PARAMETERS)
        .map(|index| format!("  p{index}:\n    type: integer\n    min: 1\n    max: 2\n"))
        .collect();
    let text = document(&format!("parameters:\n{entries}"));
    assert_eq!(invalid_field(&text)?, "parameters");
    Ok(())
}


#[test]
fn oversized_manifest_is_refused_after_bounded_read() -> TestResult {
    let padding = format!("# {}\n", "x".repeat(MAX_MANIFEST_BYTES));
    let text = document(&padding);
    let error = refusal(read_manifest(text.as_bytes(), "m.yaml"))?;
    assert!(matches!(error, ScriptError::ManifestTooLarge { max } if max == MAX_MANIFEST_BYTES));
    let exact = document("").len();
    let filler = format!("#{}\n", "x".repeat(MAX_MANIFEST_BYTES - exact - FRAME));
    let full = document(&filler);
    assert_eq!(full.len(), MAX_MANIFEST_BYTES);
    read_manifest(full.as_bytes(), "m.yaml")?;
    Ok(())
}


#[test]
fn read_failure_keeps_its_cause() -> TestResult {
    let error = refusal(read_manifest(FailingReader, "m.yaml"))?;
    assert!(matches!(error, ScriptError::Config(_)));
    assert!(error.to_string().contains("m.yaml"));
    Ok(())
}


#[test]
fn files_are_loaded_from_disk() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("cleanup.yaml");
    std::fs::write(&path, document(""))?;
    assert_eq!(load_manifest(&path)?.name, "cleanup-logs");
    let missing = refusal(load_manifest(&directory.path().join("absent.yaml")))?;
    assert!(matches!(missing, ScriptError::Config(_)));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_fifo_is_refused_without_blocking() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("pipe.yaml");
    let status = std::process::Command::new("mkfifo").arg(&path).status()?;
    assert!(status.success());
    let error = refusal(load_manifest(&path))?;
    assert!(matches!(error, ScriptError::NotRegularFile(_)));
    let folder = refusal(load_manifest(directory.path()))?;
    assert!(matches!(folder, ScriptError::Config(_) | ScriptError::NotRegularFile(_)));
    Ok(())
}
