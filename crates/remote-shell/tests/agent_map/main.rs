#[path = "../common/types.rs"]
mod common_types;
mod types;


use common_types::TestResult;
use core_audit::error::AuditError;
use core_audit::log::{append, genesis_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::error::ConfigError;
use core_config::parse::MAX_FILE_BYTES;
use core_config::reload::{current_config, reload, ReloadContext, ReloadOutcome};
use core_config::types::SharedAuditFn;
use remote_shell::agent_map::{
    agent_state, open_agent_engine, parse_agent_map, refused_feature, resolve_agent, AgentMap, ANCHORS_REFUSED, MAX_AGENT_ASSETS,
    MAX_AGENT_MAP_LINE_BYTES,
};
use serde_saphyr::granit_parser::{Event, Span};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use types::Recorded;


const TENANT: &str = "tenant-a";


const FILE: &str = "remote-shell-agents.yaml";


const STATE_SIZE: usize = 2;


const LONG_AGENT_ID: usize = 65;


const HIDING_PADDING: usize = 5000;


const HIDDEN_PADDING: usize = 180;


const BLOCK_ENTRIES: usize = 200;


fn parse(text: &str) -> Result<AgentMap, ConfigError> {
    parse_agent_map(&mut text.as_bytes(), FILE, TENANT)
}


fn refusal(text: &str) -> Result<String, io::Error> {
    parse(text)
        .err()
        .map(|error| error.to_string())
        .ok_or_else(|| io::Error::other("the file was accepted"))
}


fn file_text(entries: &[(&str, &str)]) -> String {
    let lines: String = entries
        .iter()
        .map(|(agent_id, asset)| format!("  - agent_id: {agent_id}\n    asset: {asset}\n"))
        .collect();
    format!("tenant: {TENANT}\nagents:\n{lines}")
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "remote-shell".to_owned(),
        tenant: TENANT.to_owned(),
        module: "remote-shell".to_owned(),
        target: FILE.to_owned(),
        request_id: "agent-map-reload".to_owned(),
    }
}


fn recording_audit() -> (Box<SharedAuditFn>, Recorded) {
    let recorded: Recorded = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorded);
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| {
        sink.lock().map_err(|_| AuditError::LogPoisoned)?.push(entry.clone());
        append(&log, entry)
    };
    (Box::new(audit), recorded)
}


fn recorded_entries(recorded: &Recorded) -> Result<Vec<NewEntry>, io::Error> {
    recorded.lock().map(|guard| guard.clone()).map_err(|_| io::Error::other("poisoned"))
}


fn put_file(path: &Path, text: &str) -> io::Result<()> {
    fs::write(path, text)
}


#[test]
fn a_good_file_resolves_byte_exact_assets() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1"), ("agent-2", "db.main")]))?;
    let identity = resolve_agent(&map, TENANT, "srv1").ok_or("srv1 unresolved")?;
    assert_eq!(identity.agent_id, "agent-1");
    assert_eq!(identity.tenant, TENANT);
    assert!(resolve_agent(&map, TENANT, "SRV1").is_none());
    assert!(resolve_agent(&map, TENANT, "unknown").is_none());
    Ok(())
}


#[test]
fn another_tenant_never_resolves() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1")]))?;
    assert!(resolve_agent(&map, "tenant-b", "srv1").is_none());
    assert!(resolve_agent(&map, "TENANT-A", "srv1").is_none());
    Ok(())
}


#[test]
fn state_has_one_key_per_asset() -> TestResult {
    let map = parse(&file_text(&[("agent-1", "srv1"), ("agent-2", "srv2")]))?;
    let state = agent_state(&map);
    assert_eq!(state.len(), STATE_SIZE);
    assert_eq!(state.get("agents.srv1").map(String::as_str), Some("agent-1"));
    Ok(())
}


#[test]
fn a_duplicate_asset_is_refused_naming_both_indexes() -> TestResult {
    let text = refusal(&file_text(&[("agent-1", "srv1"), ("agent-2", "srv2"), ("agent-3", "srv1")]))?;
    assert!(text.contains("agents[2].asset repeats agents[0].asset"), "{text}");
    Ok(())
}


#[test]
fn a_case_only_duplicate_asset_is_refused() -> TestResult {
    let text = refusal(&file_text(&[("agent-1", "srv1"), ("agent-2", "SRV1")]))?;
    assert!(text.contains("agents[1].asset repeats agents[0].asset"), "{text}");
    Ok(())
}


#[test]
fn a_duplicate_agent_id_is_refused_also_by_case() -> TestResult {
    let same = refusal(&file_text(&[("agent-1", "srv1"), ("agent-1", "srv2")]))?;
    assert!(same.contains("agents[1].agent_id repeats agents[0].agent_id"), "{same}");
    let folded = refusal(&file_text(&[("Agent-1", "srv1"), ("agent-1", "srv2")]))?;
    assert!(folded.contains("agents[1].agent_id repeats agents[0].agent_id"), "{folded}");
    Ok(())
}


#[test]
fn another_tenant_in_the_file_is_refused() -> TestResult {
    let text = refusal("tenant: tenant-b\nagents:\n  - agent_id: a\n    asset: b\n")?;
    assert!(text.contains("`tenant` is not the tenant of this engine"), "{text}");
    Ok(())
}


#[test]
fn a_bad_tenant_grammar_is_refused() -> TestResult {
    let text = refusal("tenant: \"-x\"\nagents:\n  - agent_id: a\n    asset: b\n")?;
    assert!(text.contains("`tenant` is outside its grammar"), "{text}");
    Ok(())
}


#[test]
fn a_long_agent_id_is_refused_without_its_value() -> TestResult {
    let long = "a".repeat(LONG_AGENT_ID);
    let text = refusal(&file_text(&[("agent-0", "srv0"), (&long, "srv1")]))?;
    assert!(text.contains("agents[1].agent_id is outside its grammar"), "{text}");
    assert!(!text.contains(&long));
    Ok(())
}


#[test]
fn an_asset_with_escape_is_refused_without_the_escape() -> TestResult {
    let text = refusal("tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: \"srv\\e1\"\n")?;
    assert!(text.contains("agents[0]: escapes are not allowed in double-quoted strings"), "{text}");
    assert!(!text.contains('\u{1b}'));
    let raw = refusal("tenant: tenant-a\nagents:\n  - agent_id: agent-1\n    asset: 'srv\\e1'\n")?;
    assert!(raw.contains("agents[0].asset is outside its grammar"), "{raw}");
    assert!(!raw.contains('\u{1b}'));
    Ok(())
}


#[test]
fn unknown_fields_are_refused() -> TestResult {
    refusal("tenant: tenant-a\nagents: []\nextra: 1\n")?;
    let text = refusal("tenant: tenant-a\nagents:\n  - agent_id: a\n    asset: b\n    more: c\n")?;
    assert!(text.contains("unknown field, expected one of"), "{text}");
    Ok(())
}


fn many_entries(count: usize) -> String {
    let lines: String = (0..count).map(|i| format!("  - agent_id: a{i}\n    asset: s{i}\n")).collect();
    format!("tenant: {TENANT}\nagents:\n{lines}")
}


#[test]
fn the_entry_cap_is_exact() -> TestResult {
    let map = parse(&many_entries(MAX_AGENT_ASSETS))?;
    assert_eq!(map.agents.len(), MAX_AGENT_ASSETS);
    let text = refusal(&many_entries(MAX_AGENT_ASSETS + 1))?;
    assert!(text.contains("too many agent entries"), "{text}");
    Ok(())
}


#[test]
fn the_entry_after_the_cap_is_never_built() -> TestResult {
    let mut text = many_entries(MAX_AGENT_ASSETS);
    text.push_str("  - agent_id: late\n    asset: late\n    surprise: 1\n");
    let message = refusal(&text)?;
    assert!(message.contains("too many agent entries"), "{message}");
    Ok(())
}


#[test]
fn a_file_over_the_byte_cap_is_refused() -> TestResult {
    let mut text = file_text(&[("agent-1", "srv1")]);
    text.push_str(&"#".repeat(MAX_FILE_BYTES as usize));
    let message = refusal(&text)?;
    assert!(message.contains("larger than"), "{message}");
    Ok(())
}


fn comment_line_of(length: usize) -> String {
    format!("{}\n", "#".repeat(length))
}


#[test]
fn a_line_over_the_cap_is_refused_and_the_cap_is_exact() -> TestResult {
    let ok = format!("{}{}", file_text(&[("agent-1", "srv1")]), comment_line_of(MAX_AGENT_MAP_LINE_BYTES));
    assert_eq!(parse(&ok)?.agents.len(), 1);
    let crlf = format!(
        "tenant: {TENANT}\r\nagents:\r\n  - agent_id: a\r\n    asset: x\r\n{}\r\n",
        "#".repeat(MAX_AGENT_MAP_LINE_BYTES)
    );
    assert_eq!(parse(&crlf)?.agents.len(), 1);
    let long = format!("{}{}", file_text(&[("agent-1", "srv1")]), comment_line_of(MAX_AGENT_MAP_LINE_BYTES + 1));
    let message = refusal(&long)?;
    assert!(message.contains("line 5: longer than 256 bytes"), "{message}");
    assert!(!message.contains("###"), "{message}");
    Ok(())
}


#[test]
fn a_flow_entry_hidden_far_to_the_right_is_refused() -> TestResult {
    let text = format!(
        "tenant: {TENANT}\nagents: [{{agent_id: a, asset: x}},{}{{agent_id: b, asset: y}}]\n",
        " ".repeat(HIDING_PADDING)
    );
    let message = refusal(&text)?;
    assert!(message.contains("line 2: longer than 256 bytes"), "{message}");
    Ok(())
}


#[test]
fn the_reviewer_line_under_the_cap_is_refused_for_its_padding() -> TestResult {
    let line = format!(
        "agents: [{{agent_id: agent-1, asset: srv1}},{}{{agent_id: evil, asset: dc01}}]",
        " ".repeat(HIDDEN_PADDING)
    );
    assert!(line.len() < MAX_AGENT_MAP_LINE_BYTES, "{}", line.len());
    let message = refusal(&format!("tenant: {TENANT}\n{line}\n"))?;
    assert!(message.contains("line 2: runs of spaces"), "{message}");
    let single = refusal(&format!(
        "tenant: {TENANT}\nagents: [{{agent_id: agent-1, asset: srv1}}, {{agent_id: evil, asset: dc01}}]\n"
    ))?;
    assert!(single.contains("flow collections are not allowed"), "{single}");
    Ok(())
}


#[test]
fn flow_mappings_and_sequences_are_refused() -> TestResult {
    let cases = [
        format!("tenant: {TENANT}\nagents:\n  - {{agent_id: a, asset: b}}\n"),
        format!("tenant: {TENANT}\nagents:\n  - agent_id: a\n    asset: [b]\n"),
        format!("tenant: {TENANT}\nagents: [a]\n"),
        format!("tenant: {TENANT}\nagents: []\n"),
        "tenant: {x: y}\nagents:\n  - agent_id: a\n    asset: b\n".to_owned(),
    ];
    cases.iter().try_for_each(|text| {
        let shown = refusal(text)?;
        shown
            .contains("flow collections are not allowed")
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("flow refusal missing from {shown}")))
    })?;
    Ok(())
}


#[test]
fn a_block_file_of_200_entries_is_accepted() -> TestResult {
    assert_eq!(parse(&many_entries(BLOCK_ENTRIES))?.agents.len(), BLOCK_ENTRIES);
    Ok(())
}


#[test]
fn padding_after_the_indentation_is_refused_but_indentation_is_not() -> TestResult {
    let base = file_text(&[("agent-1", "srv1")]);
    assert_eq!(parse(&base)?.agents.len(), 1);
    let padded_value = base.replace("asset: srv1", &format!("asset:{}srv1", " ".repeat(HIDDEN_PADDING)));
    assert!(refusal(&padded_value)?.contains("line 4: runs of spaces inside a line are not allowed"));
    let padded_comment = format!("{base}# two  spaces\r\n");
    assert!(refusal(&padded_comment)?.contains("line 5: runs of spaces"));
    let quoted = base.replace("asset: srv1", "asset: \"a  b\"");
    assert!(refusal(&quoted)?.contains("line 4: runs of spaces"));
    let one_space = format!("{base}# one space only \n\n   \n");
    assert_eq!(parse(&one_space)?.agents.len(), 1);
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_hanging() -> TestResult {
    let dir = tempfile::tempdir()?;
    let fifo = dir.path().join(FILE);
    let status = Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success());
    let (audit, _) = recording_audit();
    let error = open_agent_engine(fifo, audit, context()).err().ok_or("a FIFO was accepted")?;
    assert!(error.to_string().contains("not a regular file"), "{error}");
    Ok(())
}


#[test]
fn a_missing_first_file_fails_the_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (audit, _) = recording_audit();
    assert!(open_agent_engine(dir.path().join(FILE), audit, context()).is_err());
    Ok(())
}


#[test]
fn a_bad_first_file_fails_the_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("a", "x"), ("b", "x")]))?;
    let (audit, _) = recording_audit();
    assert!(open_agent_engine(path, audit, context()).is_err());
    Ok(())
}


#[test]
fn a_bad_reload_keeps_the_old_mapping_and_is_audited() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("agent-1", "srv1")]))?;
    let (audit, recorded) = recording_audit();
    let engine = open_agent_engine(path.clone(), audit, context())?;
    put_file(&path, &file_text(&[("agent-1", "srv1"), ("agent-2", "srv1")]))?;
    let outcome = reload(&engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("agents[1].asset repeats agents[0].asset")));
    let snapshot = current_config(&engine);
    assert!(resolve_agent(&snapshot, TENANT, "srv1").is_some());
    let entries = recorded_entries(&recorded)?;
    assert_eq!(entries.len(), 1);
    assert!(entries.iter().all(|entry| entry.outcome == Outcome::Denied));
    Ok(())
}


#[test]
fn a_good_reload_swaps_and_removes_a_mapping() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &file_text(&[("agent-1", "srv1")]))?;
    let (audit, recorded) = recording_audit();
    let engine = open_agent_engine(path.clone(), audit, context())?;
    put_file(&path, &file_text(&[("agent-2", "srv2")]))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let snapshot = current_config(&engine);
    assert!(resolve_agent(&snapshot, TENANT, "srv1").is_none());
    assert!(resolve_agent(&snapshot, TENANT, "srv2").is_some());
    assert_eq!(recorded_entries(&recorded)?.len(), 1);
    Ok(())
}


fn marker_refusals(marker: &str) -> Vec<String> {
    let base = file_text(&[("agent-1", "srv1")]);
    let changed = |from: &str, to: String| base.replace(from, &to);
    vec![
        changed("asset: srv1", format!("asset: srv1\n    {marker}: 1")),
        changed("asset: srv1", format!("asset: srv1\n    asset: {marker}")),
        changed("asset: srv1", format!("asset: srv1\n    {marker}: 1\n    {marker}: 2")),
        changed("asset: srv1", format!("asset: {marker}/\u{1b}")),
        changed("  - agent_id: agent-1\n    asset: srv1", format!("  - {marker}")),
        changed("asset: srv1", format!("asset: {{{marker}: 1}}")),
        changed("asset: srv1", format!("asset: [{marker}]")),
        format!("tenant: {TENANT}\nagents:\n  - agent_id: a\n    {marker}: !{marker} x\n  - [{marker}"),
        format!("tenant: {TENANT}\nagents: !{marker} [1]"),
        changed("agent_id: agent-1", format!("agent_id: !{marker} agent-1")),
        changed("agent_id: agent-1", format!("agent_id: !!binary {marker}")),
        changed("asset: srv1", format!("asset: {marker}: x")),
    ]
}


#[test]
fn document_text_inside_an_entry_never_reaches_a_refusal() -> TestResult {
    let base = file_text(&[("agent-1", "srv1")]);
    ["MARKERQZX", "markerqzx"].iter().try_for_each(|marker| {
        marker_refusals(marker).iter().try_for_each(|text| {
            let error = parse(text).err().ok_or_else(|| io::Error::other(format!("expected a refusal: {text}")))?;
            let shown = format!("{error:?} {error}");
            (!shown.to_ascii_lowercase().contains(&marker.to_ascii_lowercase()))
                .then_some(())
                .ok_or_else(|| io::Error::other(format!("marker leaked: {shown}")))
        })
    })?;
    let marker = "markerqzx";
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    put_file(&path, &base)?;
    let (audit, recorded) = recording_audit();
    let engine = open_agent_engine(path.clone(), audit, context())?;
    put_file(
        &path,
        &base.replace("asset: srv1", &format!("asset: srv1\n    {marker}: 1\n    {marker}: 2")),
    )?;
    let outcome = reload(&engine);
    let audited = format!("{outcome:?} {:?}", recorded_entries(&recorded)?).to_ascii_lowercase();
    assert!(!audited.contains(marker), "{audited}");
    Ok(())
}


#[test]
fn tags_are_refused_with_the_entry_index() -> TestResult {
    let two = |second: &str| format!("tenant: {TENANT}\nagents:\n  - agent_id: agent-1\n    asset: srv1\n{second}");
    let cases = [
        (two("  - agent_id: !foo agent-2\n    asset: srv2\n"), "agents[1]: tags are not allowed"),
        (two("  - agent_id: !!str agent-2\n    asset: srv2\n"), "agents[1]: tags are not allowed"),
        (two("  - agent_id: !!int agent-2\n    asset: srv2\n"), "agents[1]: tags are not allowed"),
        (
            two("  - agent_id: !!binary YWdlbnQtMg==\n    asset: srv2\n"),
            "agents[1]: tags are not allowed",
        ),
        (
            two("  - !!map\n    agent_id: agent-2\n    asset: srv2\n"),
            "agents[1]: tags are not allowed",
        ),
        (two("  - agent_id: agent-2\n    !foo asset: srv2\n"), "agents[1]: tags are not allowed"),
        (format!("tenant: {TENANT}\nagents: !!seq []\n"), "tags are not allowed"),
        (format!("!!map\ntenant: {TENANT}\nagents: []\n"), "tags are not allowed"),
        (format!("tenant: !!str {TENANT}\nagents: []\n"), "tags are not allowed"),
    ];
    cases.iter().try_for_each(|(text, expected)| {
        let shown = refusal(text)?;
        shown
            .contains(expected)
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("{expected} missing from {shown}")))
    })?;
    Ok(())
}


#[test]
fn bare_numbers_and_booleans_are_refused_but_quoted_ones_are_accepted() -> TestResult {
    let bare = [
        ("asset: 12", "agents[0].asset"),
        ("asset: true", "agents[0].asset"),
        ("agent_id: 7", "agents[0].agent_id"),
    ];
    bare.iter().try_for_each(|(change, path)| {
        let text = file_text(&[("agent-1", "srv1")]).replace(
            &change.replace(": 12", ": srv1").replace(": true", ": srv1").replace(": 7", ": agent-1"),
            change,
        );
        let shown = refusal(&text)?;
        shown
            .contains(&format!("{path} is not a plain or quoted string"))
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("{path} missing from {shown}")))
    })?;
    let quoted = parse(&file_text(&[("\"7\"", "'12'")]))?;
    assert_eq!(quoted.agents.get("12").map(String::as_str), Some("7"));
    Ok(())
}


#[test]
fn escapes_anchors_aliases_and_merge_keys_are_refused() -> TestResult {
    let two = |first: &str, second: &str| format!("tenant: {TENANT}\nagents:\n  - {first}\n  - {second}\n");
    let cases = [
        (
            two("agent_id: agent-1\n    asset: srv1", "agent_id: \"\\x61gent-2\"\n    asset: srv2"),
            "agents[1]: escapes are not allowed",
        ),
        (
            two("agent_id: agent-1\n    asset: srv1", "agent_id: \"agent\\U0000002d2\"\n    asset: srv2"),
            "agents[1]: escapes are not allowed",
        ),
        (
            two("agent_id: agent-1\n    asset: srv1", "agent_id: \"agent-2\\\n      x\"\n    asset: srv2"),
            "agents[1]: escapes are not allowed",
        ),
        (
            two("agent_id: agent-1\n    asset: &a box1", "agent_id: *a\n    asset: srv2"),
            "agents[0]: anchors, aliases and merge keys are not allowed",
        ),
        (
            two("agent_id: agent-1\n    asset: srv1", "<<: {agent_id: agent-2}\n    asset: srv2"),
            "agents[1]: anchors, aliases and merge keys are not allowed",
        ),
        (
            two("&e agent_id: agent-1\n    asset: srv1", "agent_id: agent-2\n    asset: srv2"),
            "agents[0]: anchors, aliases and merge keys are not allowed",
        ),
        (
            format!("tenant: &t {TENANT}\nagents: []\n"),
            "anchors, aliases and merge keys are not allowed",
        ),
        (
            format!("tenant: {TENANT}\nagents: &s []\n"),
            "anchors, aliases and merge keys are not allowed",
        ),
        (
            "x: &m {a: b}\ntenant: *m\nagents: []\n".to_owned(),
            "anchors, aliases and merge keys are not allowed",
        ),
        ("tenant:\n  !foo a: b\nagents: []\n".to_owned(), "tags are not allowed"),
    ];
    cases.iter().try_for_each(|(text, expected)| {
        let shown = refusal(text)?;
        shown
            .contains(expected)
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("{expected} missing from {shown}")))
    })?;
    let under_tenant = refusal("tenant:\n  !foo a: b\nagents: []\n")?;
    assert!(!under_tenant.contains("agents["), "{under_tenant}");
    let other_key = refusal("tenant:\n  - x\n  - !foo y\nagents: []\n")?;
    assert!(!other_key.contains("agents["), "{other_key}");
    Ok(())
}


#[test]
fn quoted_values_without_escapes_are_accepted() -> TestResult {
    let doubled = refusal(&file_text(&[("\"agent-1\"", "'it''s'")]))?;
    assert!(doubled.contains("agents[0].asset is outside its grammar"), "{doubled}");
    let plain = parse(&file_text(&[("\"agent-1\"", "'srv-1'"), ("'agent-2'", "\"srv-2\"")]))?;
    assert_eq!(plain.agents.get("srv-2").map(String::as_str), Some("agent-2"));
    Ok(())
}


#[test]
fn block_scalars_are_refused() -> TestResult {
    ["|-", "|", ">-", ">"].iter().try_for_each(|header| {
        let text = format!("tenant: {TENANT}\nagents:\n  - agent_id: {header}\n      agent-3\n    asset: srv3\n");
        let shown = refusal(&text)?;
        shown
            .contains("agents[0]: block scalars are not allowed")
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("missing from {shown}")))
    })?;
    Ok(())
}


#[test]
fn an_alias_event_is_refused_even_without_its_anchor() -> TestResult {
    let span = Span::default();
    assert_eq!(refused_feature(&Event::Alias(1), &span, ""), Some(ANCHORS_REFUSED));
    assert_eq!(refused_feature(&Event::UnresolvedAlias("a".into()), &span, ""), Some(ANCHORS_REFUSED));
    Ok(())
}


#[test]
fn bytes_outside_printable_ascii_refuse_the_whole_file_naming_the_line() -> TestResult {
    let ok = file_text(&[("agent-1", "srv1")]);
    let hostile = [
        "# srv9 retired\r  - agent_id: agent-2\n",
        "# a\u{2028}  - agent_id: agent-2\n",
        "# a\u{85}b\n",
        "# a\u{2029}b\n",
        "\u{feff}x: 1\n",
        "# tab\there\n",
        "# caf\u{e9}\n",
        "# nul\u{0}\n",
        "# a\u{202e}b\n",
    ];
    hostile.iter().try_for_each(|extra| {
        let shown = refusal(&format!("{ok}{extra}"))?;
        let expected = format!("line {}", ok.matches('\n').count() + 1);
        shown
            .contains(&expected)
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("{expected} missing from {shown}")))?;
        let bytes: Vec<char> = extra.chars().filter(|ch| !ch.is_ascii() || ch.is_control() && *ch != '\n').collect();
        bytes
            .iter()
            .all(|ch| !shown.contains(*ch))
            .then_some(())
            .ok_or_else(|| io::Error::other(format!("byte leaked: {shown}")))
    })?;
    let crlf = parse(&ok.replace('\n', "\r\n"))?;
    assert_eq!(crlf.agents.len(), 1);
    let trailing_cr = refusal(&format!("{ok}\r"))?;
    assert!(trailing_cr.contains("only printable ASCII"), "{trailing_cr}");
    Ok(())
}
