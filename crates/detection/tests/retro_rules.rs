#![cfg(unix)]

#[path = "retro_rules/types.rs"]
mod types;


use alerts::store::MAX_RULE_ID_CHARS;
use detection::retro_rules::{candidate_of, select_retro_rules, usable_id, Candidate, LOSS_ID_PREFIX};
use sigma_sql::mapping::{parse_mapping, FieldMapping};
use std::collections::BTreeMap;
use std::error::Error;
use stream_correlation::base::BaseRule;
use stream_correlation::ruleset::{parse_ruleset, RuleSet};
use types::TestResult;


const MAPPING: &str = include_str!("../../sigma-sql/mappings/ecs.yaml");


const TWO: usize = 2;


const HASH_CHARS: usize = 64;


fn mapping() -> Result<FieldMapping, Box<dyn Error>> {
    Ok(parse_mapping(MAPPING)?)
}


fn rule_text(id: Option<&str>, tags: &[&str]) -> String {
    let id_line = id.map_or_else(String::new, |text| format!("id: {text}\n"));
    let tag_lines: String = tags.iter().map(|tag| format!("  - '{tag}'\n")).collect();
    let tag_block = if tags.is_empty() { String::new() } else { format!("tags:\n{tag_lines}") };
    format!(
        "title: Rule {}\n{id_line}level: high\n{tag_block}logsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\n",
        id.unwrap_or("none")
    )
}


fn ruleset(texts: &[String]) -> Result<RuleSet, Box<dyn Error>> {
    let named: BTreeMap<String, String> = texts
        .iter()
        .enumerate()
        .map(|(index, text)| (format!("r{index}.yml"), text.clone()))
        .collect();
    Ok(parse_ruleset(&named, &mapping()?)?)
}


fn base(id: Option<&str>, tags: &[&str]) -> Result<BaseRule, Box<dyn Error>> {
    ruleset(&[rule_text(id, tags)])?.bases.into_iter().next().ok_or_else(|| "no base".into())
}


fn selected(candidate: Candidate) -> Result<detection::retro_rules::RetroRule, Box<dyn Error>> {
    match candidate {
        Candidate::Selected(rule) => Ok(rule),
        other => Err(format!("{other:?}").into()),
    }
}


#[test]
fn only_the_exact_tag_selects_a_rule_with_prefixed_ids_and_a_source_fingerprint() -> TestResult {
    let tagged = selected(candidate_of(&base(Some("base-1"), &["attack.t1110", "ostyr.retro"])?))?;
    assert_eq!((tagged.rule_id.as_str(), tagged.loss_id.as_str()), ("retro:base-1", "retro.loss:base-1"));
    assert_eq!(tagged.title, "Rule base-1");
    assert_eq!(tagged.fingerprint.len(), HASH_CHARS);
    assert!(tagged.source.contains("EventID: 4625"));
    ["OSTYR.RETRO", "ostyr.retro.x", "ostyr.retr", " ostyr.retro", "ostyr.retro "]
        .iter()
        .try_for_each(|tag| -> TestResult {
            assert_eq!(candidate_of(&base(Some("base-1"), &[tag])?), Candidate::NotRetro);
            Ok(())
        })?;
    assert_eq!(candidate_of(&base(Some("base-1"), &[])?), Candidate::NotRetro);
    Ok(())
}


#[test]
fn an_edit_changes_the_fingerprint_and_keeps_the_ids() -> TestResult {
    let before = selected(candidate_of(&base(Some("base-1"), &["ostyr.retro"])?))?;
    let after = selected(candidate_of(&base(Some("base-1"), &["ostyr.retro", "x.y"])?))?;
    assert_ne!(before.fingerprint, after.fingerprint);
    assert_eq!((before.rule_id, before.loss_id), (after.rule_id, after.loss_id));
    Ok(())
}


#[test]
fn a_tagged_rule_without_a_usable_id_is_skipped() -> TestResult {
    assert_eq!(candidate_of(&base(None, &["ostyr.retro"])?), Candidate::Skipped);
    let long = "x".repeat(MAX_RULE_ID_CHARS - LOSS_ID_PREFIX.len() + 1);
    assert_eq!(candidate_of(&base(Some(&long), &["ostyr.retro"])?), Candidate::Skipped);
    let fits = "x".repeat(MAX_RULE_ID_CHARS - LOSS_ID_PREFIX.len());
    assert!(matches!(candidate_of(&base(Some(&fits), &["ostyr.retro"])?), Candidate::Selected(_)));
    assert!(!usable_id(""));
    assert!(!usable_id("a\u{1}b"));
    assert!(!usable_id("a\u{2028}b"));
    assert!(usable_id("a-b"));
    let mut broken = base(Some("base-1"), &["ostyr.retro"])?;
    broken.source = "title: [".to_owned();
    assert_eq!(candidate_of(&broken), Candidate::Skipped);
    Ok(())
}


#[test]
fn a_rule_set_yields_its_retro_rules_and_counts_the_skipped_ones() -> TestResult {
    let set = ruleset(&[
        rule_text(Some("kept-1"), &["ostyr.retro"]),
        rule_text(Some("live-only"), &[]),
        rule_text(None, &["ostyr.retro"]),
        rule_text(Some("kept-2"), &["ostyr.retro"]),
    ])?;
    let selection = select_retro_rules(&set);
    let ids: Vec<&str> = selection.rules.iter().map(|rule| rule.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["retro:kept-1", "retro:kept-2"]);
    assert_eq!(selection.skipped, 1);
    assert_eq!(selection.rules.len(), TWO);
    let clean = select_retro_rules(&ruleset(&[rule_text(Some("live-only"), &[])])?);
    assert_eq!((clean.rules.len(), clean.skipped), (0, 0));
    Ok(())
}
