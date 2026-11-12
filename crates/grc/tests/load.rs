#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use grc::error::GrcError;
use grc::load::{
    check_framework, is_identifier, is_printable_text, load_framework, parse_framework, MAX_AGE_HOURS, MAX_CONTROLS, MAX_FILE_BYTES, MAX_ID_CHARS,
    MAX_INDICATOR_CHARS, MAX_TITLE_CHARS,
};
use grc::model::{Control, ControlKind, Framework, Threshold};
use std::io::Read;
use types::TestResult;


const NAN_THRESHOLD: f64 = f64::NAN;


const CONTROL_COUNT: usize = 3;


const AT_MOST_COMPLIANT: f64 = 72.0;


const STEP: f64 = 1.0;


const LIMIT: f64 = 90.0;


const LOOSER: f64 = 70.0;


const ANCHOR_LEVELS: usize = 12;


const VALID: &str = "framework: demo-1
version: 1
controls:
  - id: A.5.1
    title: Policies are written and reviewed
    kind: organisational
  - id: KEV-MTTF
    title: Known exploited flaws are fixed fast
    kind: technical
    indicator: kev.mean_time_to_fix_hours
    max_age_hours: 24
    compliant:
      at_most: 72
    partial:
      at_most: 168
  - id: EDR
    title: Share of devices with anti-malware
    kind: technical
    indicator: edr.share
    max_age_hours: 48
    compliant: {at_least: 95}
    partial: {at_least: 80}
";


fn parse(text: &str) -> Result<Framework, GrcError> {
    parse_framework(&mut text.as_bytes(), "f.yaml")
}


fn reason_of(result: Result<Framework, GrcError>) -> String {
    match result {
        Err(GrcError::Invalid { reason, .. }) => reason,
        Err(other) => other.to_string(),
        Ok(_) => "accepted".to_owned(),
    }
}


fn technical() -> Control {
    Control {
        id: "T1".to_owned(),
        title: "title".to_owned(),
        kind: ControlKind::Technical,
        indicator: Some("edr.share".to_owned()),
        max_age_hours: Some(1),
        compliant: Some(Threshold::AtLeast(LIMIT)),
        partial: Some(Threshold::AtLeast(LOOSER)),
    }
}


fn framework_of(controls: Vec<Control>) -> Framework {
    Framework {
        framework: "demo".to_owned(),
        version: 1,
        controls,
    }
}


fn reason_of_control(control: Control) -> String {
    reason_of(check_framework(&framework_of(vec![control]), "f.yaml").map(|()| framework_of(Vec::new())))
}


#[test]
fn a_valid_framework_loads() -> TestResult {
    let framework = parse(VALID)?;
    assert_eq!(framework.framework, "demo-1");
    assert_eq!(framework.controls.len(), CONTROL_COUNT);
    let first = framework.controls.first().ok_or("no control")?;
    assert_eq!(first.kind, ControlKind::Organisational);
    let second = framework.controls.get(1).ok_or("no control")?;
    assert_eq!(second.compliant, Some(Threshold::AtMost(AT_MOST_COMPLIANT)));
    Ok(())
}


#[test]
fn a_framework_loads_from_a_path_and_a_missing_one_fails() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("f.yaml");
    std::fs::write(&path, VALID)?;
    assert_eq!(load_framework(&path)?.controls.len(), CONTROL_COUNT);
    assert!(matches!(
        load_framework(&directory.path().join("absent.yaml")),
        Err(GrcError::Config(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn identifiers_follow_the_grammar() -> TestResult {
    assert!(is_identifier("A.5.1", MAX_ID_CHARS));
    assert!(is_identifier("a", MAX_ID_CHARS));
    for refused in ["", "-x", ".x", "a b", "a\u{202E}b", "a/b", "é"] {
        assert!(!is_identifier(refused, MAX_ID_CHARS), "{refused:?}");
    }
    assert!(is_identifier(&"a".repeat(MAX_ID_CHARS), MAX_ID_CHARS));
    assert!(!is_identifier(&"a".repeat(MAX_ID_CHARS + 1), MAX_ID_CHARS));
    Ok(())
}


#[test]
fn printable_text_refuses_control_and_invisible_characters() -> TestResult {
    assert!(is_printable_text("Own wording: access reviews", MAX_TITLE_CHARS));
    assert!(is_printable_text(&"é".repeat(MAX_TITLE_CHARS), MAX_TITLE_CHARS));
    assert!(!is_printable_text(&"é".repeat(MAX_TITLE_CHARS + 1), MAX_TITLE_CHARS));
    for refused in [
        "",
        "   ",
        "a\u{0}b",
        "a\nb",
        "a\u{7}b",
        "a\u{061C}b",
        "a\u{200B}b",
        "a\u{200F}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{202A}b",
        "a\u{202E}b",
        "a\u{2066}b",
        "a\u{2069}b",
        "a\u{FEFF}b",
    ] {
        assert!(!is_printable_text(refused, MAX_TITLE_CHARS), "{refused:?}");
    }
    Ok(())
}


#[test]
fn unknown_fields_and_wrong_types_are_refused() -> TestResult {
    assert!(parse("framework: d\nversion: 1\ncontrols: []\nextra: 1\n").is_err());
    let word_threshold = VALID.replace("at_least: 95", "at_least: high");
    assert!(parse(&word_threshold).is_err());
    let bad_kind = VALID.replace("kind: organisational", "kind: manual");
    assert!(parse(&bad_kind).is_err());
    Ok(())
}


#[test]
fn a_quoted_number_reads_as_the_same_number() -> TestResult {
    let quoted = parse(&VALID.replace("at_least: 95", "at_least: \"95\""))?;
    let plain = parse(VALID)?;
    assert_eq!(quoted, plain);
    Ok(())
}


#[test]
fn a_non_finite_yaml_threshold_never_loads() -> TestResult {
    for word in [".nan", ".inf", "-.inf"] {
        let text = VALID.replace("at_least: 95", &format!("at_least: {word}"));
        assert!(parse(&text).is_err(), "{word}");
    }
    Ok(())
}


#[test]
fn a_non_finite_threshold_is_refused_by_the_check() -> TestResult {
    let mut nan_compliant = technical();
    nan_compliant.compliant = Some(Threshold::AtLeast(NAN_THRESHOLD));
    assert_eq!(reason_of_control(nan_compliant), "control 0: thresholds must be finite numbers");
    let mut infinite_partial = technical();
    infinite_partial.partial = Some(Threshold::AtLeast(f64::INFINITY));
    assert_eq!(reason_of_control(infinite_partial), "control 0: thresholds must be finite numbers");
    Ok(())
}


#[test]
fn thresholds_must_share_a_direction_and_partial_must_be_looser() -> TestResult {
    let mut mixed = technical();
    mixed.partial = Some(Threshold::AtMost(LOOSER));
    assert_eq!(reason_of_control(mixed), "control 0: thresholds must use the same direction");
    let mut mixed_back = technical();
    mixed_back.compliant = Some(Threshold::AtMost(LIMIT));
    assert_eq!(reason_of_control(mixed_back), "control 0: thresholds must use the same direction");
    let mut stricter_least = technical();
    stricter_least.partial = Some(Threshold::AtLeast(LIMIT + STEP));
    assert_eq!(reason_of_control(stricter_least), "control 0: partial is stricter than compliant");
    let mut stricter_most = technical();
    stricter_most.compliant = Some(Threshold::AtMost(LOOSER));
    stricter_most.partial = Some(Threshold::AtMost(LOOSER - STEP));
    assert_eq!(reason_of_control(stricter_most), "control 0: partial is stricter than compliant");
    let mut equal = technical();
    equal.partial = Some(Threshold::AtLeast(LIMIT));
    assert_eq!(reason_of_control(equal), "accepted");
    Ok(())
}


#[test]
fn a_technical_control_needs_its_fields() -> TestResult {
    let mut no_indicator = technical();
    no_indicator.indicator = None;
    assert_eq!(reason_of_control(no_indicator), "control 0: technical control needs a valid indicator");
    let mut bad_indicator = technical();
    bad_indicator.indicator = Some("-bad".to_owned());
    assert_eq!(reason_of_control(bad_indicator), "control 0: technical control needs a valid indicator");
    let mut long_indicator = technical();
    long_indicator.indicator = Some("a".repeat(MAX_INDICATOR_CHARS + 1));
    assert_eq!(reason_of_control(long_indicator), "control 0: technical control needs a valid indicator");
    for age in [None, Some(0), Some(MAX_AGE_HOURS + 1)] {
        let mut subject = technical();
        subject.max_age_hours = age;
        assert_eq!(
            reason_of_control(subject),
            "control 0: technical control needs max_age_hours between 1 and 8760"
        );
    }
    let mut at_limit = technical();
    at_limit.max_age_hours = Some(MAX_AGE_HOURS);
    assert_eq!(reason_of_control(at_limit), "accepted");
    let mut no_compliant = technical();
    no_compliant.compliant = None;
    assert_eq!(
        reason_of_control(no_compliant),
        "control 0: technical control needs compliant and partial thresholds"
    );
    let mut no_partial = technical();
    no_partial.partial = None;
    assert_eq!(
        reason_of_control(no_partial),
        "control 0: technical control needs compliant and partial thresholds"
    );
    Ok(())
}


#[test]
fn an_organisational_control_carries_no_indicator_field() -> TestResult {
    let plain = Control {
        id: "O".to_owned(),
        title: "policy".to_owned(),
        kind: ControlKind::Organisational,
        indicator: None,
        max_age_hours: None,
        compliant: None,
        partial: None,
    };
    assert_eq!(reason_of_control(plain.clone()), "accepted");
    let mut with_indicator = plain.clone();
    with_indicator.indicator = Some("edr.share".to_owned());
    let mut with_age = plain.clone();
    with_age.max_age_hours = Some(1);
    let mut with_compliant = plain.clone();
    with_compliant.compliant = Some(Threshold::AtLeast(LIMIT));
    let mut with_partial = plain;
    with_partial.partial = Some(Threshold::AtLeast(LIMIT));
    for subject in [with_indicator, with_age, with_compliant, with_partial] {
        assert_eq!(
            reason_of_control(subject),
            "control 0: organisational control must not carry indicator fields"
        );
    }
    Ok(())
}


#[test]
fn control_ids_and_titles_are_checked() -> TestResult {
    for id in ["-x", "a\u{202E}b", "", "a b"] {
        let mut subject = technical();
        subject.id = id.to_owned();
        assert_eq!(reason_of_control(subject), "control 0: invalid id");
    }
    for title in ["", "a\u{202E}b", &"t".repeat(MAX_TITLE_CHARS + 1)] {
        let mut subject = technical();
        subject.title = title.to_owned();
        assert_eq!(reason_of_control(subject), "control 0: invalid title");
    }
    Ok(())
}


#[test]
fn duplicate_control_ids_are_refused() -> TestResult {
    let framework = framework_of(vec![technical(), technical()]);
    assert!(matches!(
        check_framework(&framework, "f.yaml"),
        Err(GrcError::Invalid { reason, .. }) if reason == "control 1: duplicate id"
    ));
    Ok(())
}


#[test]
fn the_framework_id_is_checked() -> TestResult {
    let mut framework = framework_of(Vec::new());
    framework.framework = "-demo".to_owned();
    assert!(matches!(
        check_framework(&framework, "f.yaml"),
        Err(GrcError::Invalid { reason, .. }) if reason == "invalid framework id"
    ));
    Ok(())
}


fn many_controls(count: usize) -> String {
    let header = "framework: big\nversion: 1\ncontrols:\n".to_owned();
    (0..count).fold(header, |text, index| {
        text + &format!("  - id: C{index}\n    title: Control {index}\n    kind: organisational\n")
    })
}


#[test]
fn the_control_count_is_capped() -> TestResult {
    assert_eq!(parse(&many_controls(MAX_CONTROLS))?.controls.len(), MAX_CONTROLS);
    assert_eq!(
        reason_of(parse(&many_controls(MAX_CONTROLS + 1))),
        format!("more than {MAX_CONTROLS} controls")
    );
    Ok(())
}


#[test]
fn an_oversized_file_is_refused_before_it_is_buffered() -> TestResult {
    let mut endless = std::io::repeat(b'a').take(MAX_FILE_BYTES + 1);
    assert!(matches!(
        parse_framework(&mut endless, "f.yaml"),
        Err(GrcError::Config(ConfigError::TooLarge { .. }))
    ));
    Ok(())
}


#[test]
fn an_alias_bomb_is_refused() -> TestResult {
    let levels = (1..ANCHOR_LEVELS).fold("l0: &l0 [x, x, x, x, x, x, x, x, x]\n".to_owned(), |text, level| {
        let previous = level - 1;
        text + &format!("l{level}: &l{level} [*l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}, *l{previous}]\n")
    });
    let bomb = format!("framework: bomb\nversion: 1\ncontrols: []\n{levels}");
    assert!(parse(&bomb).is_err());
    Ok(())
}
