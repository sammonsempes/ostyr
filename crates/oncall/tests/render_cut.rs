#[path = "common/types.rs"]
mod types;


use oncall::limits::{MAX_RENDER_ENTRIES, SMS_BODY_LEN};
use oncall::model::{AlertNotice, Channel, ChannelKind};
use oncall::render::{render, section};
use std::collections::BTreeMap;
use types::TestResult;


const EXTRA: usize = 8;


fn labels(count: usize) -> BTreeMap<String, String> {
    (0..count).map(|i| (format!("l{i:02}"), "v".to_string())).collect()
}


fn notice(count: usize) -> AlertNotice {
    AlertNotice {
        tenant: "acme".to_string(),
        name: "down".to_string(),
        labels: labels(count),
        annotations: BTreeMap::new(),
    }
}


fn channel(kind: ChannelKind) -> Channel {
    Channel {
        name: "c".to_string(),
        tenant: "acme".to_string(),
        kind,
        target: "https://example.com".to_string(),
        secret_file: None,
    }
}


#[test]
fn a_section_over_the_cap_starts_with_a_visible_count() -> TestResult {
    let text = section("label", &labels(MAX_RENDER_ENTRIES + EXTRA));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), MAX_RENDER_ENTRIES + 1);
    assert_eq!(lines.first().copied(), Some("label (8 not shown)"));
    let exact = section("label", &labels(MAX_RENDER_ENTRIES));
    assert_eq!(exact.lines().count(), MAX_RENDER_ENTRIES);
    assert!(!exact.contains("not shown"));
    Ok(())
}


#[test]
fn every_kind_shows_the_count_even_when_cut() -> TestResult {
    let kinds = [
        ChannelKind::Slack,
        ChannelKind::Teams,
        ChannelKind::Webhook,
        ChannelKind::Ntfy,
        ChannelKind::Smtp,
        ChannelKind::Sms,
    ];
    kinds.iter().try_for_each(|kind| -> TestResult {
        let message = render(&notice(MAX_RENDER_ENTRIES + EXTRA), &channel(*kind))?;
        let text = if *kind == ChannelKind::Webhook {
            let parsed: serde_json::Value = serde_json::from_str(&message.body)?;
            parsed.get("text").and_then(|value| value.as_str()).ok_or("no text field")?.to_string()
        } else {
            message.body
        };
        let plain = text.replace('\\', "");
        assert!(plain.starts_with("label (8 not shown)"), "{kind:?}: {plain}");
        Ok(())
    })
}


#[test]
fn sms_is_still_cut_to_its_own_bound() -> TestResult {
    let message = render(&notice(MAX_RENDER_ENTRIES + EXTRA), &channel(ChannelKind::Sms))?;
    assert_eq!(message.body.chars().count(), SMS_BODY_LEN);
    Ok(())
}
