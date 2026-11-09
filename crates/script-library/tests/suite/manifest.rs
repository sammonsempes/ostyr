use crate::common::{manifest_with, refusal, single, EMPTY_SHA256};
use crate::types::TestResult;
use script_library::check::{check_manifest, is_identifier, is_library_path, is_sha256_hex};
use script_library::error::ScriptError;
use script_library::load::read_manifest;
use script_library::model::{
    Interpreter, Limits, Manifest, ParamKind, DEFAULT_MEMORY_BYTES, DEFAULT_PIDS, MAX_CPU_PERCENT, MAX_MEMORY_BYTES, MAX_NAME_LENGTH,
    MAX_PATTERN_LENGTH, MAX_PIDS, MAX_SECRET_PATTERNS, MIN_MEMORY_BYTES, REDACTION_SLACK_BYTES, SHA256_HEX_LENGTH,
};
use script_library::pattern::{compile_secret_pattern, ensure_match_bounded, maximum_match_bytes};
use script_library::redact::{redact, redact_capped};


#[test]
fn well_formed_manifest_passes() -> TestResult {
    check_manifest(&manifest_with(Interpreter::Python, vec![]))?;
    check_manifest(&single("days", ParamKind::Integer { min: 0, max: 1 }))?;
    Ok(())
}


#[test]
fn identifiers() -> TestResult {
    assert!(is_identifier("a"));
    assert!(is_identifier("a-b_9"));
    assert!(is_identifier(&format!("a{}", "b".repeat(MAX_NAME_LENGTH - 1))));
    assert!(!is_identifier(""));
    assert!(!is_identifier("9a"));
    assert!(!is_identifier("A"));
    assert!(!is_identifier("a b"));
    assert!(!is_identifier(&format!("a{}", "b".repeat(MAX_NAME_LENGTH))));
    Ok(())
}


#[test]
fn library_paths() -> TestResult {
    assert!(is_library_path("linux/cleanup.sh"));
    assert!(is_library_path("a.ps1"));
    ["", "/a", "\\a", "-a", "a\\b", "a\u{1}b", "a//b", "a/", "a/./b", "a/../b", ".."]
        .iter()
        .for_each(|path| assert!(!is_library_path(path), "{path:?}"));
    Ok(())
}


#[test]
fn digests() -> TestResult {
    assert!(is_sha256_hex(&"a".repeat(SHA256_HEX_LENGTH)));
    assert!(!is_sha256_hex(&"a".repeat(SHA256_HEX_LENGTH - 1)));
    assert!(!is_sha256_hex(&"A".repeat(SHA256_HEX_LENGTH)));
    Ok(())
}


pub const DECLARED_PIDS: u64 = 5;


fn with_secrets(patterns: Vec<String>) -> Manifest {
    Manifest {
        secret_patterns: patterns,
        ..manifest_with(Interpreter::Bash, vec![])
    }
}


fn with_limits(limits: Limits) -> Manifest {
    Manifest {
        limits,
        ..manifest_with(Interpreter::Bash, vec![])
    }
}


#[test]
fn secret_patterns_are_bounded_and_whole_value_checked() -> TestResult {
    check_manifest(&with_secrets(vec!["token-[a-z0-9]{1,20}".to_string(); MAX_SECRET_PATTERNS]))?;
    let bad = |patterns: Vec<String>| check_manifest(&with_secrets(patterns)).is_err();
    assert!(bad(vec!["a".to_string(); MAX_SECRET_PATTERNS + 1]));
    assert!(bad(vec!["a)|(b".to_string()]));
    assert!(bad(vec!["a".repeat(MAX_PATTERN_LENGTH + 1)]));
    assert!(bad(vec![String::new()]));
    assert!(bad(vec!["a*".to_string()]));
    assert!(bad(vec!["tok-[0-9]+".to_string()]));
    assert!(bad(vec![".{1,5}|x+".to_string()]));
    Ok(())
}


#[test]
fn a_secret_pattern_that_only_the_bytes_compiler_refuses_is_refused() -> TestResult {
    assert!(matches!(
        refusal(compile_secret_pattern("(?-u:\\xff)\\p{Greek}"))?,
        ScriptError::Pattern(_)
    ));
    Ok(())
}


#[test]
fn the_longest_match_of_a_secret_pattern_is_bounded_by_the_slack() -> TestResult {
    assert_eq!(maximum_match_bytes("tok-[0-9]{1,20}")?, Some(TOKEN_MATCH_BYTES));
    assert_eq!(maximum_match_bytes("tok-[0-9]+")?, None);
    assert!(matches!(refusal(maximum_match_bytes("("))?, ScriptError::Pattern(_)));
    ensure_match_bounded(Some(REDACTION_SLACK_BYTES as usize), REDACTION_SLACK_BYTES)?;
    assert!(ensure_match_bounded(Some(REDACTION_SLACK_BYTES as usize + 1), REDACTION_SLACK_BYTES).is_err());
    assert!(ensure_match_bounded(None, REDACTION_SLACK_BYTES).is_err());
    assert!(ensure_match_bounded(Some(usize::MAX), 1).is_err());
    Ok(())
}


#[test]
fn limits_default_and_stay_within_their_bounds() -> TestResult {
    let defaults = Limits::default();
    assert_eq!(
        (defaults.memory_bytes, defaults.pids, defaults.cpu_percent),
        (DEFAULT_MEMORY_BYTES, DEFAULT_PIDS, None)
    );
    check_manifest(&with_limits(defaults))?;
    let at_maximum = Limits {
        memory_bytes: MAX_MEMORY_BYTES,
        pids: MAX_PIDS,
        cpu_percent: Some(MAX_CPU_PERCENT),
    };
    check_manifest(&with_limits(at_maximum))?;
    let bad = |limits: Limits| check_manifest(&with_limits(limits)).is_err();
    assert!(bad(Limits {
        memory_bytes: MIN_MEMORY_BYTES - 1,
        ..at_maximum
    }));
    assert!(bad(Limits {
        memory_bytes: MAX_MEMORY_BYTES + 1,
        ..at_maximum
    }));
    assert!(bad(Limits { pids: 0, ..at_maximum }));
    assert!(bad(Limits {
        pids: MAX_PIDS + 1,
        ..at_maximum
    }));
    assert!(bad(Limits {
        cpu_percent: Some(0),
        ..at_maximum
    }));
    assert!(bad(Limits {
        cpu_percent: Some(MAX_CPU_PERCENT + 1),
        ..at_maximum
    }));
    Ok(())
}


#[test]
fn limits_and_patterns_come_from_the_yaml_manifest() -> TestResult {
    let text = format!(
        "name: a\ninterpreter: bash\nscript: a.sh\nsha256: {EMPTY_SHA256}\ntimeout_seconds: 1\nmax_output_bytes: 1\nsecret_patterns: ['k-[0-9]{{1,20}}']\nlimits:\n  pids: 5\n"
    );
    let manifest = read_manifest(text.as_bytes(), "m.yaml")?;
    assert_eq!(manifest.limits.pids, DECLARED_PIDS);
    assert_eq!(manifest.limits.memory_bytes, DEFAULT_MEMORY_BYTES);
    assert_eq!(manifest.secret_patterns, vec!["k-[0-9]{1,20}".to_string()]);
    let unknown = text.replace("pids: 5", "swap: 5");
    assert!(read_manifest(unknown.as_bytes(), "m.yaml").is_err());
    Ok(())
}


#[test]
fn redaction_replaces_every_match_and_ignores_empty_ones() -> TestResult {
    let token = compile_secret_pattern("tok-[0-9]{1,20}")?;
    let digits = compile_secret_pattern("[0-9]{3}")?;
    let boundary = compile_secret_pattern(r"\b")?;
    assert_eq!(
        redact(b"a tok-1 b tok-22".to_vec(), std::slice::from_ref(&token)),
        b"a [REDACTED] b [REDACTED]"
    );
    assert_eq!(redact(b"x tok-1 111".to_vec(), &[token.clone(), digits]), b"x [REDACTED] [REDACTED]");
    assert_eq!(redact(b"no secret".to_vec(), &[boundary]), b"no secret");
    assert_eq!(redact(b"tok-1".to_vec(), &[]), b"tok-1");
    assert_eq!(redact(b"\xff tok-1".to_vec(), &[token]), b"\xff [REDACTED]");
    Ok(())
}


pub const TOKEN_MATCH_BYTES: usize = 24;


#[test]
fn overlapping_patterns_leak_nothing_and_marks_are_never_rewritten() -> TestResult {
    let short = compile_secret_pattern("abc")?;
    let long = compile_secret_pattern("xabcdefgh")?;
    assert_eq!(redact(b"token xabcdefgh end".to_vec(), &[short, long]), b"token [REDACTED] end");
    let prefix = compile_secret_pattern("tok[0-9]{4}")?;
    let mark = compile_secret_pattern(r"\[RED")?;
    assert_eq!(redact(b"tok1234".to_vec(), &[prefix, mark]), b"[REDACTED]");
    Ok(())
}


pub const LONG_TEXT_BYTES: usize = 1000;


pub const REPEATS: usize = 100;


pub const WIDE_BOUNDARY: usize = 500;


pub const SMALL_CAP: usize = 25;


pub const CAP_ACCOUNTED: usize = 6;


pub const WHOLE: usize = 100;


pub const TEXT_END: usize = 10;


pub const PLAIN_CAP: usize = 4;


pub const STRADDLE_BOUNDARY: usize = 4;


pub const STRADDLE_ACCOUNTED: usize = 6;


pub const CONTEXT_BOUNDARY: usize = 3;


#[test]
fn many_overlapping_patterns_do_not_grow_the_output() -> TestResult {
    let patterns = ["[a-z]", "[A-Z]", "[A-Z]", "[A-Z]"]
        .map(compile_secret_pattern)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(redact(vec![b'a'; LONG_TEXT_BYTES], &patterns), b"[REDACTED]");
    let (output, consumed) = redact_capped(&b"a b c".repeat(REPEATS), &patterns, WIDE_BOUNDARY, SMALL_CAP);
    assert_eq!(output.len(), SMALL_CAP);
    assert_eq!(consumed, CAP_ACCOUNTED);
    Ok(())
}


#[test]
fn a_cut_inside_plain_text_counts_only_the_kept_bytes() -> TestResult {
    let token = compile_secret_pattern("tok")?;
    let (output, consumed) = redact_capped(b"abcdef tok", std::slice::from_ref(&token), TEXT_END, PLAIN_CAP);
    assert_eq!((output, consumed), (b"abcd".to_vec(), PLAIN_CAP));
    let (straddling, accounted) = redact_capped(b"ab tok cd", std::slice::from_ref(&token), STRADDLE_BOUNDARY, WHOLE);
    assert_eq!((straddling, accounted), (b"ab [REDACTED]".to_vec(), STRADDLE_ACCOUNTED));
    let (context, kept) = redact_capped(b"ab tok cd", &[token], CONTEXT_BOUNDARY, WHOLE);
    assert_eq!((context, kept), (b"ab ".to_vec(), CONTEXT_BOUNDARY));
    Ok(())
}
