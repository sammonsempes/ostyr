#[path = "common/types.rs"]
mod types;


use core_config::strict::{
    allowed_byte, feature_reason, refuse_features, refuse_forbidden_bytes, Rules, ANCHORS_REFUSED, BLOCKS_REFUSED, ESCAPES_REFUSED, FLOW_REFUSED,
    TAGS_REFUSED,
};
use serde_saphyr::granit_parser::{Event, Parser, Span};
use types::TestResult;


const FILE: &str = "list.yaml";


const OUT_OF_RANGE: usize = 5;


const ALIAS_ID: usize = 7;


const INVALID: &str = "the document is not valid";


const BLOCK_RULES: Rules<'static> = Rules {
    list_key: "items",
    invalid_text: INVALID,
    allow_flow: false,
    show_line: false,
};


const LINE_RULES: Rules<'static> = Rules {
    show_line: true,
    allow_flow: true,
    ..BLOCK_RULES
};


fn reason_of(result: Result<(), core_config::error::ConfigError>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(result.err().ok_or("expected a refusal")?.to_string())
}


#[test]
fn a_clean_block_file_passes() -> TestResult {
    refuse_forbidden_bytes("tenant: a\nitems:\n  - name: x\r\n    other: \"plain\"\n", FILE)?;
    refuse_features("tenant: a\nitems:\n  - name: x\n    other: \"plain\"\n", FILE, BLOCK_RULES)?;
    refuse_features("items:\n  - name: x\n", FILE, LINE_RULES)?;
    Ok(())
}


#[test]
fn bytes_outside_the_allowlist_name_the_line_only() -> TestResult {
    ["a\n\tb", "a\nb\rc", "a\nb\u{e9}", "a\nb\u{feff}", "a\nb\u{2028}", "a\nb\u{0}", "a\r"]
        .iter()
        .try_for_each(|text| -> TestResult {
            let reason = reason_of(refuse_forbidden_bytes(text, FILE))?;
            assert!(reason.contains("only printable ASCII and line breaks are allowed"), "{reason}");
            assert!(reason.contains("line"), "{reason}");
            Ok(())
        })?;
    assert!(reason_of(refuse_forbidden_bytes("a\nb\nc\td", FILE))?.contains("line 3:"));
    assert!(allowed_byte(b"a\r\n", 1));
    assert!(!allowed_byte(b"a", OUT_OF_RANGE));
    Ok(())
}


#[test]
fn every_feature_is_refused_with_its_reason() -> TestResult {
    let cases = [
        ("items:\n  - name: !!str x\n", TAGS_REFUSED),
        ("items:\n  - !foo\n    name: x\n", TAGS_REFUSED),
        ("items:\n  - name: &a x\n", ANCHORS_REFUSED),
        ("items:\n  - name: &a x\n  - name: *a\n", ANCHORS_REFUSED),
        ("base: &b {k: v}\nitems:\n  - <<: *b\n", ANCHORS_REFUSED),
        ("items:\n  - <<: x\n", ANCHORS_REFUSED),
        ("items:\n  - name: \"a\\x61\"\n", ESCAPES_REFUSED),
        ("items:\n  - name: |\n      text\n", BLOCKS_REFUSED),
        ("items:\n  - name: >\n      text\n", BLOCKS_REFUSED),
        ("items: [a]\n", FLOW_REFUSED),
        ("items:\n  - {name: x}\n", FLOW_REFUSED),
    ];
    cases.iter().try_for_each(|(text, expected)| -> TestResult {
        let reason = reason_of(refuse_features(text, FILE, BLOCK_RULES))?;
        assert!(reason.contains(expected), "{text}: {reason}");
        Ok(())
    })
}


#[test]
fn a_feature_inside_an_entry_names_the_index_and_never_the_value() -> TestResult {
    let reason = reason_of(refuse_features(
        "tenant: a\nitems:\n  - name: ok\n  - name: !!str SECRETMARK\n",
        FILE,
        BLOCK_RULES,
    ))?;
    assert!(reason.contains("items[1]: tags are not allowed"), "{reason}");
    assert!(!reason.contains("SECRETMARK"));
    let root = reason_of(refuse_features("tenant: !!str a\n", FILE, BLOCK_RULES))?;
    assert!(root.ends_with("tags are not allowed"), "{root}");
    assert!(!root.contains("items["));
    let other_key = reason_of(refuse_features("other:\n  - !!str x\n", FILE, BLOCK_RULES))?;
    assert!(!other_key.contains("items["), "{other_key}");
    Ok(())
}


#[test]
fn the_line_is_named_when_asked() -> TestResult {
    let reason = reason_of(refuse_features("items:\n  - name: ok\n  - name: &a x\n", FILE, LINE_RULES))?;
    assert!(reason.contains("line 3: items[1]: anchors"), "{reason}");
    let root = reason_of(refuse_features("a: 1\nb: !!str x\n", FILE, LINE_RULES))?;
    assert!(root.contains("line 2: tags"), "{root}");
    Ok(())
}


#[test]
fn flow_is_admitted_only_when_allowed() -> TestResult {
    refuse_features("items: [a, b]\nmap: {k: v}\n", FILE, LINE_RULES)?;
    assert!(refuse_features("items: [a]\n", FILE, BLOCK_RULES).is_err());
    Ok(())
}


#[test]
fn a_syntax_error_has_the_given_text() -> TestResult {
    let reason = reason_of(refuse_features("items: [a\n", FILE, LINE_RULES))?;
    assert!(reason.contains(INVALID), "{reason}");
    Ok(())
}


#[test]
fn an_alias_event_is_refused_without_its_anchor() -> TestResult {
    let text = "a: 1\n";
    let alias = Event::Alias(ALIAS_ID);
    let span = Span::default();
    assert_eq!(feature_reason(&alias, &span, text, true), Some(ANCHORS_REFUSED));
    assert_eq!(
        feature_reason(&Event::UnresolvedAlias("x".into()), &span, text, true),
        Some(ANCHORS_REFUSED)
    );
    Ok(())
}


#[test]
fn a_missing_source_slice_is_refused_for_escapes_and_flow() -> TestResult {
    let text = "- \"x\"\n- [a]\n";
    let events: Vec<(Event<'_>, Span)> = Parser::new_from_str(text).collect::<Result<_, _>>()?;
    let scalar = events.iter().find(|(item, _)| matches!(item, Event::Scalar(..))).ok_or("no scalar")?;
    assert_eq!(feature_reason(&scalar.0, &scalar.1, text, false), None);
    assert_eq!(feature_reason(&scalar.0, &scalar.1, "", false), Some(ESCAPES_REFUSED));
    let inner = events
        .iter()
        .filter(|(item, _)| matches!(item, Event::SequenceStart(..)))
        .nth(1)
        .ok_or("no flow")?;
    assert_eq!(feature_reason(&inner.0, &inner.1, text, false), Some(FLOW_REFUSED));
    assert_eq!(feature_reason(&inner.0, &inner.1, "", false), Some(FLOW_REFUSED));
    assert_eq!(feature_reason(&inner.0, &inner.1, text, true), None);
    Ok(())
}
