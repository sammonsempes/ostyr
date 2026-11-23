#[path = "support/types.rs"]
mod types;


use types::TestResult;
use web_ui::api::{valid_report_framework, MAX_REPORT_FRAMEWORK_CHARS};


const GRC_MAX_ID_CHARS: usize = 64;


fn corpus() -> Vec<String> {
    let mut samples: Vec<String> = (0..=u8::MAX).map(|byte| char::from(byte).to_string()).collect();
    samples.extend((0..=u8::MAX).map(|byte| format!("a{}", char::from(byte))));
    samples.extend(
        [MAX_REPORT_FRAMEWORK_CHARS - 1, MAX_REPORT_FRAMEWORK_CHARS, MAX_REPORT_FRAMEWORK_CHARS + 1]
            .iter()
            .flat_map(|length| ["a".repeat(*length), format!("-{}", "a".repeat(*length)), "\u{e9}".repeat(*length)]),
    );
    samples.extend(["", "-a", "a-", "a\u{3164}", "\u{ff21}bc", "a b", "a/b", "a&b=c"].map(String::from));
    samples
}


#[test]
fn the_framework_grammar_agrees_with_grc_on_a_corpus() -> TestResult {
    assert_eq!(MAX_REPORT_FRAMEWORK_CHARS, GRC_MAX_ID_CHARS);
    for sample in corpus() {
        assert_eq!(
            valid_report_framework(&sample),
            grc::load::is_identifier(&sample, GRC_MAX_ID_CHARS),
            "{sample:?}"
        );
    }
    Ok(())
}
