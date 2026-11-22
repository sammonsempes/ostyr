use crate::api::{
    encode_asset_id, parse_dhcp_address, parse_dhcp_mac, risk_kind, valid_asset_id, valid_case_id, valid_dhcp_hostname, valid_id, valid_oncall_text,
    valid_pack_id, valid_shell_hash, valid_shell_reference, valid_shell_subject, valid_state_asset, valid_state_id, valid_vuln_asset,
    valid_vuln_field, vuln_score, CERT_FILTERS, MAX_COMMENT_CHARS, MAX_NOTE_CHARS, MAX_ONCALL_FINGERPRINT_BYTES, MAX_RISK_VALUE,
    MAX_SHELL_REFERENCE_BYTES, MAX_SHELL_SUBJECT_BYTES, MAX_STATE_ID_CHARS, MIN_SHELL_FRAMES, RISK_KINDS, RUN_CHANGED_KEY, SHELL_OPEN_ONLY,
    STATE_VERDICTS, VERDICT_ALL, VULN_CVSS_MAX, VULN_EPSS_MAX,
};
use crate::model::{
    Alert, AlertDetailView, AlertPage, AssetDetailView, AssetPageView, AssetSummaryView, CaseDetailView, CasePageView, CaseSummaryView,
    CertDetailView, CertListView, CertView, CommentView, FindingView, FindingsView, Language, LeaseView, LookupView, OncallAlertView, OncallListView,
    PostureFindingView, PostureRunView, PostureView, RiskDetailView, RiskEntityView, RiskListView, RiskTruncatedView, ShellEnd, ShellFacts,
    ShellListView, ShellQuery, ShellSessionView, StateAssetView, StateListView, StateView, TriageView, VulnAssetView, VulnListView, VulnView,
};
use crate::strings::{
    action_key, allowed_actions, case_severity_class, case_severity_key, dhcp_action_key, language_tag, posture_severity_key, posture_status_key,
    resolution_key, severity_class, severity_key, shell_reason_key, status_key, task_status_key, text, triage_key, CLOSE_ACTION, RESOLUTIONS,
    TRIAGE_STATUSES,
};
use ecs_normalise::suricata::{is_unsafe, REPLACEMENT};
use maud::{html, Markup, DOCTYPE};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};


pub const MAX_FIELD_CHARS: usize = 256;


pub const MAX_VALUE_CHARS: usize = 512;


pub const MAX_SUMMARY_ENTRIES: usize = 64;


pub const MAX_EVENT_IDS: usize = 50;


pub const MAX_TEXT_CHARS: usize = 4096;


pub const MAX_COMMENT_LINES: usize = 64;


pub const MAX_TASKS: usize = 64;


pub const MAX_ROW_DNS_NAMES: usize = 20;


pub const MAX_DETAIL_DNS_NAMES: usize = 100;


pub const STYLESHEET: &str = "body{font-family:sans-serif;margin:0;color:#1b1f23}header{display:flex;gap:1rem;align-items:center;padding:.5rem 1rem;\
background:#1b1f23;color:#fff}header button{color:#fff;background:none;border:0;font:inherit;cursor:pointer;text-decoration:underline}\
main{padding:1rem}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ccc;padding:.4rem;text-align:left}\
.sev-low{color:#0a6}.sev-medium{color:#b80}.sev-high{color:#c30}.sev-critical{color:#c00;font-weight:bold}\
form.go{display:inline;margin:0}td button,main>form.go button{color:#06c}label{display:block;margin:.5rem 0}.notice{color:#c00}\
.absent{color:#666;font-style:italic}dt{font-weight:bold}\
main>form{margin:.5rem 0}textarea{display:block;width:100%;min-height:6rem}.comment{white-space:pre-wrap;border:1px solid #ccc;padding:.5rem}";


/// Text from the API or any peer: control and bidirectional-override characters replaced by U+FFFD, long values cut with a visible count.
pub fn clip(language: Language, value: &str, max: usize) -> String {
    let shown: String = value
        .chars()
        .map(|character| if displayable(character) { character } else { REPLACEMENT })
        .collect();
    let omitted = shown.chars().count().saturating_sub(max);
    if omitted == 0 {
        shown
    } else {
        let kept: String = shown.chars().take(max).collect();
        format!("{kept}... [{omitted} {}]", text(language, "omitted"))
    }
}


/// Identity text: `clip`, plus every whitespace character except a lone inner U+0020 shown as U+FFFD, so no look-alike of another name renders alike.
pub fn clip_identity(language: Language, value: &str, max: usize) -> String {
    let mapped: Vec<char> = value
        .chars()
        .map(|character| if displayable(character) { character } else { REPLACEMENT })
        .collect();
    let before = std::iter::once(None).chain(mapped.iter().copied().map(Some));
    let after = mapped.iter().skip(1).copied().map(Some).chain(std::iter::once(None));
    let marked: String = mapped
        .iter()
        .copied()
        .zip(before)
        .zip(after)
        .map(|((character, previous), next)| {
            if character.is_whitespace() && !(character == ' ' && inner_neighbour(previous) && inner_neighbour(next)) {
                REPLACEMENT
            } else {
                character
            }
        })
        .collect();
    clip(language, &marked, max)
}


pub fn inner_neighbour(neighbour: Option<char>) -> bool {
    neighbour.is_some_and(|character| !character.is_whitespace())
}


/// A DNS name is IA5String (IDNs are `xn--` labels): `clip_identity`, plus every non-ASCII character shown as U+FFFD.
pub fn clip_dns(language: Language, value: &str, max: usize) -> String {
    let ascii: String = value
        .chars()
        .map(|character| if character.is_ascii() { character } else { REPLACEMENT })
        .collect();
    clip_identity(language, &ascii, max)
}


pub fn displayable(character: char) -> bool {
    !is_unsafe(character)
}


pub fn optional(language: Language, value: Option<&String>) -> String {
    value.map_or_else(|| text(language, "none").to_owned(), |present| clip(language, present, MAX_FIELD_CHARS))
}


pub fn optional_identity(language: Language, value: Option<&String>) -> Markup {
    value.map_or_else(
        || html! { span class="absent" { (text(language, "none_marker")) } },
        |present| html! { (clip_identity(language, present, MAX_FIELD_CHARS)) },
    )
}


pub fn display_identity(language: Language, value: &Value) -> String {
    match value {
        Value::String(plain) => clip_identity(language, plain, MAX_VALUE_CHARS),
        other => clip_identity(language, &other.to_string(), MAX_VALUE_CHARS),
    }
}


pub fn display_value(language: Language, value: &Value) -> String {
    match value {
        Value::String(plain) => clip(language, plain, MAX_VALUE_CHARS),
        other => clip(language, &other.to_string(), MAX_VALUE_CHARS),
    }
}


/// Navigation is a GET form with a button styled as a link: no anchor, and the target is a fixed path or an API-validated identifier.
pub fn go(action: &str, label: &str) -> Markup {
    html! {
        form method="get" action=(action) class="go" { button type="submit" { (label) } }
    }
}


/// The language switch is a POST form: its token is the session's or the login cookie's, so a page without one offers no switch.
pub fn switch_form(code: &str, label: &str, token: &str) -> Markup {
    html! {
        form method="post" action=(format!("/language/{code}")) class="go" {
            input type="hidden" name="csrf" value=(token);
            button type="submit" { (label) }
        }
    }
}


pub fn layout(language: Language, title_key: &str, csrf: Option<&str>, body: Markup) -> Markup {
    layout_with(language, title_key, csrf, csrf, body)
}


pub fn layout_with(language: Language, title_key: &str, csrf: Option<&str>, switch: Option<&str>, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang=(language_tag(language)) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (text(language, title_key)) " - " (text(language, "app_name")) }
                link rel="stylesheet" href="/style.css";
            }
            body {
                header {
                    strong { (text(language, "app_name")) }
                    @if let Some(token) = csrf {
                        (go("/alerts", text(language, "nav_alerts")))
                        (go("/cases", text(language, "nav_cases")))
                        (go("/assets", text(language, "nav_assets")))
                        (go("/risk", text(language, "nav_risk")))
                        (go("/certificates", text(language, "nav_certs")))
                        (go("/hunts", text(language, "nav_hunts")))
                        (go("/compliance", text(language, "nav_compliance")))
                        (go("/vulnerabilities", text(language, "nav_vulns")))
                        (go("/dhcp", text(language, "nav_dhcp")))
                        (go("/posture", text(language, "nav_posture")))
                        (go("/oncall", text(language, "nav_oncall")))
                        (go("/remote-shell", text(language, "nav_shell")))
                        form method="post" action="/logout" {
                            input type="hidden" name="csrf" value=(token);
                            button type="submit" { (text(language, "nav_logout")) }
                        }
                    }
                    @if let Some(token) = switch {
                        (switch_form("en", text(language, "nav_language_en"), token))
                        (switch_form("fr", text(language, "nav_language_fr"), token))
                    }
                }
                main { (body) }
            }
        }
    }
}


pub fn login_page(language: Language, csrf: &str, failed: bool) -> Markup {
    layout_with(
        language,
        "title_login",
        None,
        Some(csrf),
        html! {
            h1 { (text(language, "title_login")) }
            @if failed {
                div class="notice" { (text(language, "login_failed")) }
            }
            form method="post" action="/login" {
                input type="hidden" name="csrf" value=(csrf);
                label { (text(language, "login_username")) input type="text" name="username" autocomplete="username" required maxlength="256"; }
                label { (text(language, "login_password")) input type="password" name="password" autocomplete="current-password" required maxlength="1024"; }
                label { (text(language, "login_totp")) input type="text" name="totp_code" autocomplete="one-time-code" maxlength="16"; }
                button type="submit" { (text(language, "login_submit")) }
            }
        },
    )
}


pub fn error_page(language: Language, csrf: Option<&str>, message_key: &str) -> Markup {
    layout(
        language,
        "title_error",
        csrf,
        html! {
            h1 { (text(language, "title_error")) }
            div { (text(language, message_key)) }
        },
    )
}


pub fn alert_row(language: Language, alert: &Alert) -> Markup {
    html! {
        tr {
            td class=(severity_class(alert.severity)) { (text(language, severity_key(alert.severity))) }
            td { (go(&format!("/alerts/{}", alert.id), &clip(language, &alert.rule_title, MAX_FIELD_CHARS))) }
            td { (optional_identity(language, alert.host_name.as_ref())) }
            td { (optional_identity(language, alert.user_name.as_ref())) }
            td { (clip(language, &alert.event_time, MAX_FIELD_CHARS)) }
        }
    }
}


pub fn alerts_page(language: Language, csrf: &str, page: &AlertPage) -> Markup {
    layout(
        language,
        "title_alerts",
        Some(csrf),
        html! {
            h1 { (text(language, "title_alerts")) }
            @if page.items.is_empty() {
                div { (text(language, "alerts_empty")) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_severity")) }
                            th { (text(language, "col_rule")) }
                            th { (text(language, "col_host")) }
                            th { (text(language, "col_user")) }
                            th { (text(language, "col_time")) }
                        }
                    }
                    tbody {
                        @for alert in &page.items { (alert_row(language, alert)) }
                    }
                }
            }
            @if let Some(cursor) = &page.next_cursor {
                form method="get" action="/alerts" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    button type="submit" { (text(language, "alerts_next")) }
                }
            }
        },
    )
}


pub fn summary_list(language: Language, summary: &Map<String, Value>) -> Markup {
    let omitted = summary.len().saturating_sub(MAX_SUMMARY_ENTRIES);
    html! {
        dl {
            @for (name, value) in summary.iter().take(MAX_SUMMARY_ENTRIES) {
                dt { (clip_identity(language, name, MAX_FIELD_CHARS)) }
                dd { (display_identity(language, value)) }
            }
        }
        @if omitted > 0 {
            div { (omitted) " " (text(language, "omitted")) }
        }
    }
}


pub fn event_list(language: Language, ids: &[String]) -> Markup {
    let omitted = ids.len().saturating_sub(MAX_EVENT_IDS);
    html! {
        ul {
            @for id in ids.iter().take(MAX_EVENT_IDS) { li { (clip_identity(language, id, MAX_FIELD_CHARS)) } }
        }
        @if omitted > 0 {
            div { (omitted) " " (text(language, "omitted")) }
        }
    }
}


/// The triage read with the page, or the fixed "new" text.
pub fn triage_summary(language: Language, triage: Option<&TriageView>) -> Markup {
    html! {
        h2 { (text(language, "triage_heading")) }
        @if let Some(current) = triage {
            dl {
                dt { (text(language, "triage_status")) }
                dd { (text(language, triage_key(&current.status))) }
                dt { (text(language, "triage_actor")) }
                dd { (clip_identity(language, &current.actor, MAX_FIELD_CHARS)) }
                dt { (text(language, "triage_time")) }
                dd { (clip(language, &current.updated_at, MAX_FIELD_CHARS)) }
                dt { (text(language, "triage_note")) }
                dd { (description_text(language, current.note.as_ref())) }
            }
        } @else {
            div { (text(language, "triage_new")) }
        }
    }
}


/// The triage form: the version read with the page rides along as a hidden field, absent while the alert is new.
pub fn triage_form(language: Language, csrf: &str, id: &str, triage: Option<&TriageView>) -> Markup {
    html! {
        form method="post" action=(format!("/alerts/{id}/triage")) {
            input type="hidden" name="csrf" value=(csrf);
            @if let Some(current) = triage {
                input type="hidden" name="version" value=(current.version);
            }
            label {
                (text(language, "triage_status"))
                select name="status" required {
                    @for status in TRIAGE_STATUSES { option value=(status) { (text(language, triage_key(status))) } }
                }
            }
            label {
                (text(language, "triage_note_label"))
                textarea name="note" maxlength=(MAX_NOTE_CHARS) {}
            }
            button type="submit" { (text(language, "triage_submit")) }
        }
    }
}


pub fn alert_page(language: Language, csrf: &str, detail: &AlertDetailView) -> Markup {
    let alert = &detail.alert;
    layout(
        language,
        "title_alert",
        Some(csrf),
        html! {
            h1 { (clip(language, &alert.rule_title, MAX_FIELD_CHARS)) }
            dl {
                dt { (text(language, "col_severity")) }
                dd class=(severity_class(alert.severity)) { (text(language, severity_key(alert.severity))) }
                dt { (text(language, "alert_rule_id")) }
                dd { (clip_identity(language, &alert.rule_id, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_host")) }
                dd { (optional_identity(language, alert.host_name.as_ref())) }
                dt { (text(language, "col_user")) }
                dd { (optional_identity(language, alert.user_name.as_ref())) }
                dt { (text(language, "col_time")) }
                dd { (clip(language, &alert.event_time, MAX_FIELD_CHARS)) }
                dt { (text(language, "alert_created")) }
                dd { (clip(language, &alert.created, MAX_FIELD_CHARS)) }
            }
            h2 { (text(language, "alert_events")) }
            (event_list(language, &alert.event_ids))
            h2 { (text(language, "alert_summary")) }
            @if alert.summary_truncated {
                div { (text(language, "alert_summary_truncated")) }
            }
            (summary_list(language, &alert.summary))
            (triage_summary(language, detail.triage.as_ref()))
            (triage_form(language, csrf, &alert.id, detail.triage.as_ref()))
            (go("/alerts", text(language, "alert_back")))
        },
    )
}


/// Unix seconds as UTC RFC 3339; a value outside the calendar is the fixed "unknown" text.
pub fn format_time(language: Language, seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .unwrap_or_else(|| text(language, "unknown").to_owned())
}


/// A case id is a link only inside the id grammar; any other id is text with a fixed marker.
pub fn case_title_cell(language: Language, case: &CaseSummaryView) -> Markup {
    let title = clip(language, &case.title, MAX_FIELD_CHARS);
    html! {
        @if valid_case_id(&case.id) {
            (go(&format!("/cases/{}", case.id), &title))
        } @else {
            (title) " [" (text(language, "not_linkable")) "]"
        }
    }
}


pub fn case_row(language: Language, case: &CaseSummaryView) -> Markup {
    html! {
        tr {
            td class=(case_severity_class(&case.severity)) { (text(language, case_severity_key(&case.severity))) }
            td { (case_title_cell(language, case)) }
            td { (text(language, status_key(&case.status))) }
            td { (optional_identity(language, case.assignee.as_ref())) }
            td { (format_time(language, case.updated_at)) }
        }
    }
}


pub fn cases_page(language: Language, csrf: &str, page: &CasePageView, limit: Option<u32>) -> Markup {
    layout(
        language,
        "title_cases",
        Some(csrf),
        html! {
            h1 { (text(language, "title_cases")) }
            @if page.items.is_empty() {
                div { (text(language, "cases_empty")) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_severity")) }
                            th { (text(language, "col_case_title")) }
                            th { (text(language, "col_status")) }
                            th { (text(language, "col_assignee")) }
                            th { (text(language, "col_updated")) }
                        }
                    }
                    tbody {
                        @for case in &page.items { (case_row(language, case)) }
                    }
                }
            }
            @if let Some(cursor) = &page.next_cursor {
                form method="get" action="/cases" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    @if let Some(kept) = limit {
                        input type="hidden" name="limit" value=(kept);
                    }
                    button type="submit" { (text(language, "cases_next")) }
                }
            }
        },
    )
}


/// A list row is readable only when its id may become a link and its kind and life cycle hold no character `is_unsafe` refuses.
pub fn asset_readable(asset: &AssetSummaryView) -> bool {
    valid_asset_id(&asset.id) && !asset.kind.chars().any(is_unsafe) && !asset.lifecycle.chars().any(is_unsafe)
}


pub fn asset_row(language: Language, asset: &AssetSummaryView) -> Markup {
    if asset_readable(asset) {
        asset_row_readable(language, asset)
    } else {
        html! {
            tr { td colspan="6" { (text(language, "asset_unreadable")) } }
        }
    }
}


pub fn asset_row_readable(language: Language, asset: &AssetSummaryView) -> Markup {
    let link = format!("/assets/{}", encode_asset_id(&asset.id));
    html! {
        tr {
            td { (go(&link, &asset.id)) }
            td { (clip_identity(language, &asset.kind, MAX_FIELD_CHARS)) }
            td { (clip_identity(language, &asset.lifecycle, MAX_FIELD_CHARS)) }
            td { (asset.counts.keys) }
            td { (asset.counts.attributes) }
            td { (asset.counts.open_conflicts) }
        }
    }
}


pub fn assets_page(language: Language, csrf: &str, page: &AssetPageView, limit: Option<u32>) -> Markup {
    layout(
        language,
        "title_assets",
        Some(csrf),
        html! {
            h1 { (text(language, "title_assets")) }
            @if page.items.is_empty() {
                div { (text(language, "assets_empty")) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_asset_id")) }
                            th { (text(language, "col_kind")) }
                            th { (text(language, "col_lifecycle")) }
                            th { (text(language, "count_keys")) }
                            th { (text(language, "count_attributes")) }
                            th { (text(language, "count_conflicts")) }
                        }
                    }
                    tbody {
                        @for asset in &page.items { (asset_row(language, asset)) }
                    }
                }
            }
            @if let Some(cursor) = &page.next_cursor {
                form method="get" action="/assets" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    @if let Some(kept) = limit {
                        input type="hidden" name="limit" value=(kept);
                    }
                    button type="submit" { (text(language, "assets_next")) }
                }
            }
        },
    )
}


pub fn asset_page(language: Language, csrf: &str, asset: &AssetDetailView) -> Markup {
    let counts = asset.summary.counts;
    layout(
        language,
        "title_asset",
        Some(csrf),
        html! {
            h1 { (text(language, "title_asset")) " " (asset.summary.id) }
            dl {
                dt { (text(language, "col_kind")) }
                dd { (clip_identity(language, &asset.summary.kind, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_lifecycle")) }
                dd { (clip_identity(language, &asset.summary.lifecycle, MAX_FIELD_CHARS)) }
                dt { (text(language, "count_keys")) }
                dd { (counts.keys) }
                dt { (text(language, "count_attributes")) }
                dd { (counts.attributes) }
                dt { (text(language, "count_conflicts")) }
                dd { (counts.open_conflicts) }
            }
            h2 { (text(language, "asset_keys")) }
            table {
                tbody {
                    @for entry in &asset.keys {
                        tr {
                            td { (clip_identity(language, &entry.key, MAX_FIELD_CHARS)) }
                            td { (clip_identity(language, &entry.value, MAX_VALUE_CHARS)) }
                        }
                    }
                }
            }
            h2 { (text(language, "asset_attributes")) }
            table {
                thead {
                    tr {
                        th { (text(language, "col_name")) }
                        th { (text(language, "col_value")) }
                        th { (text(language, "col_source")) }
                    }
                }
                tbody {
                    @for entry in &asset.attributes {
                        tr {
                            td { (clip_identity(language, &entry.name, MAX_FIELD_CHARS)) }
                            td { (clip_identity(language, &entry.value, MAX_VALUE_CHARS)) }
                            td { (clip_identity(language, &entry.source, MAX_FIELD_CHARS)) }
                        }
                    }
                }
            }
            @if asset.truncated {
                div class="notice" { (text(language, "asset_truncated")) }
            }
            (go("/assets", text(language, "asset_back")))
        },
    )
}


pub fn case_tasks(language: Language, case: &CaseDetailView) -> Markup {
    let omitted = case.tasks.len().saturating_sub(MAX_TASKS);
    html! {
        ul {
            @for task in case.tasks.iter().take(MAX_TASKS) {
                li {
                    (clip(language, &task.title, MAX_FIELD_CHARS)) " (" (text(language, task_status_key(&task.status))) ")"
                    @if let Some(due) = task.due {
                        " " (text(language, "case_due")) " " (format_time(language, due))
                    }
                }
            }
        }
        @if omitted > 0 {
            div { (omitted) " " (text(language, "omitted")) }
        }
    }
}


pub fn case_counts(language: Language, case: &CaseDetailView) -> Markup {
    let counts = case.summary.counts;
    html! {
        dl {
            dt { (text(language, "count_tasks")) }
            dd { (counts.tasks) }
            dt { (text(language, "count_observables")) }
            dd { (counts.observables) }
            dt { (text(language, "count_comments")) }
            dd { (counts.comments) }
            dt { (text(language, "count_history")) }
            dd { (counts.history) }
            dt { (text(language, "count_alerts")) }
            dd { (counts.alerts) }
        }
    }
}


pub fn resolution_text(language: Language, resolution: Option<&String>) -> &'static str {
    resolution.map_or_else(|| text(language, "none"), |value| text(language, resolution_key(value)))
}


pub fn description_text(language: Language, description: Option<&String>) -> String {
    description.map_or_else(|| text(language, "none").to_owned(), |value| clip(language, value, MAX_TEXT_CHARS))
}


/// One POST form per action the status allows; `close` carries the resolution list of the fixed table.
pub fn action_form(language: Language, csrf: &str, id: &str, action: &str) -> Markup {
    html! {
        form method="post" action=(format!("/cases/{id}/action")) {
            input type="hidden" name="csrf" value=(csrf);
            input type="hidden" name="action" value=(action);
            @if action == CLOSE_ACTION {
                label {
                    (text(language, "case_resolution"))
                    select name="resolution" required {
                        @for resolution in RESOLUTIONS { option value=(resolution) { (text(language, resolution_key(resolution))) } }
                    }
                }
            }
            button type="submit" { (text(language, action_key(action))) }
        }
    }
}


pub fn comment_form(language: Language, csrf: &str, id: &str) -> Markup {
    html! {
        form method="post" action=(format!("/cases/{id}/comment")) {
            input type="hidden" name="csrf" value=(csrf);
            label {
                (text(language, "comment_label"))
                textarea name="text" required maxlength=(MAX_COMMENT_CHARS) {}
            }
            button type="submit" { (text(language, "comment_submit")) }
        }
    }
}


/// The write forms exist only for an id inside the case grammar, because the id becomes part of their action.
pub fn case_forms(language: Language, csrf: &str, case: &CaseDetailView) -> Markup {
    let id = &case.summary.id;
    html! {
        @if valid_case_id(id) {
            h2 { (text(language, "case_actions")) }
            @for action in allowed_actions(&case.summary.status) { (action_form(language, csrf, id, action)) }
            (comment_form(language, csrf, id))
        }
    }
}


/// The comment as the API stored it, shown after a successful post.
pub fn comment_notice(language: Language, comment: &CommentView) -> Markup {
    let omitted_lines = comment.text.lines().count().saturating_sub(MAX_COMMENT_LINES);
    html! {
        div class="comment" {
            strong { (text(language, "comment_added")) }
            " " (clip_identity(language, &comment.author, MAX_FIELD_CHARS)) " " (format_time(language, comment.at))
            div {
                @for line in comment.text.lines().take(MAX_COMMENT_LINES) {
                    (clip(language, line, MAX_TEXT_CHARS)) br;
                }
                @if omitted_lines > 0 {
                    (format!("... [{omitted_lines} {}]", text(language, "omitted")))
                }
            }
        }
    }
}


/// The page after a stored comment whose case could not be read again: the stored comment, our own text and a GET form to `target`.
pub fn comment_unloaded_page(
    language: Language,
    csrf: Option<&str>,
    comment: &CommentView,
    target: &str,
    message_key: &str,
    label_key: &str,
) -> Markup {
    layout(
        language,
        "title_case",
        csrf,
        html! {
            div { (text(language, message_key)) }
            (comment_notice(language, comment))
            (go(target, text(language, label_key)))
        },
    )
}


pub fn case_page(language: Language, csrf: &str, case: &CaseDetailView) -> Markup {
    case_page_with(language, csrf, case, None)
}


pub fn case_page_with(language: Language, csrf: &str, case: &CaseDetailView, comment: Option<&CommentView>) -> Markup {
    let summary = &case.summary;
    layout(
        language,
        "title_case",
        Some(csrf),
        html! {
            h1 { (clip(language, &summary.title, MAX_FIELD_CHARS)) }
            dl {
                dt { (text(language, "col_severity")) }
                dd class=(case_severity_class(&summary.severity)) { (text(language, case_severity_key(&summary.severity))) }
                dt { (text(language, "col_status")) }
                dd { (text(language, status_key(&summary.status))) }
                dt { (text(language, "col_assignee")) }
                dd { (optional_identity(language, summary.assignee.as_ref())) }
                dt { (text(language, "col_type")) }
                dd { (optional(language, summary.case_type.as_ref())) }
                dt { (text(language, "case_template")) }
                dd { (optional(language, case.template.as_ref())) }
                dt { (text(language, "col_created")) }
                dd { (format_time(language, summary.created_at)) }
                dt { (text(language, "col_updated")) }
                dd { (format_time(language, summary.updated_at)) }
                dt { (text(language, "case_resolution")) }
                dd { (resolution_text(language, case.resolution.as_ref())) }
            }
            h2 { (text(language, "case_description")) }
            div { (description_text(language, case.description.as_ref())) }
            h2 { (text(language, "case_tasks")) }
            (case_tasks(language, case))
            h2 { (text(language, "case_counts")) }
            (case_counts(language, case))
            @if let Some(stored) = comment { (comment_notice(language, stored)) }
            (case_forms(language, csrf, case))
            (go("/cases",text(language, "case_back")))
        },
    )
}


/// A fixed key per bound name of the risk API; any other name is the fixed "unknown" text.
pub fn risk_limit_key(limit: &str) -> &'static str {
    match limit {
        "alerts" => "risk_limit_alerts",
        "contributions" => "risk_limit_contributions",
        "entities" => "risk_limit_entities",
        _ => "unknown",
    }
}


pub fn risk_kind_key(kind: &str) -> &'static str {
    match kind {
        "host" => "risk_kind_host",
        _ => "risk_kind_user",
    }
}


/// The visible banner of a partial computation: the bound by its fixed name and the two numbers.
pub fn risk_banner(language: Language, truncated: &Option<RiskTruncatedView>) -> Markup {
    html! {
        @if let Some(bound) = truncated {
            div class="notice" {
                (text(language, "risk_truncated")
                    .replace("{limit}", text(language, risk_limit_key(&bound.limit)))
                    .replace("{read}", &bound.read.to_string())
                    .replace("{cap}", &bound.cap.to_string()))
            }
        }
    }
}


/// A row is readable only for a kind of the API, a score in 0 to 100 and an id that renders as itself.
pub fn risk_readable(entity: &RiskEntityView) -> bool {
    risk_kind(&entity.kind).is_some() && entity.value <= MAX_RISK_VALUE && valid_asset_id(&entity.id)
}


pub fn risk_bar(value: u64) -> Markup {
    html! {
        meter min="0" max=(MAX_RISK_VALUE) value=(value) { (value) } " " (value)
    }
}


pub fn risk_row(language: Language, entity: &RiskEntityView) -> Markup {
    if risk_readable(entity) {
        let link = format!("/risk/{}/{}", entity.kind, encode_asset_id(&entity.id));
        html! {
            tr {
                td { (text(language, risk_kind_key(&entity.kind))) }
                td { (go(&link, &entity.id)) }
                td { (risk_bar(entity.value)) }
                td { (entity.contributions_used) }
                td { (entity.contributions_dropped) }
            }
        }
    } else {
        html! {
            tr { td colspan="5" { (text(language, "risk_unreadable")) } }
        }
    }
}


pub fn risk_filter(language: Language) -> Markup {
    html! {
        (go("/risk", text(language, "risk_kind_all")))
        @for kind in RISK_KINDS {
            form method="get" action="/risk" class="go" {
                input type="hidden" name="kind" value=(kind);
                button type="submit" { (text(language, risk_kind_key(kind))) }
            }
        }
    }
}


pub fn risk_page(language: Language, csrf: &str, list: &RiskListView) -> Markup {
    layout(
        language,
        "title_risk",
        Some(csrf),
        html! {
            h1 { (text(language, "title_risk")) }
            (risk_filter(language))
            div { (text(language, "risk_computed")) " " (format_time(language, list.computed_at)) }
            (risk_banner(language, &list.truncated))
            @if list.entities.is_empty() {
                div { (text(language, "risk_empty")) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_kind")) }
                            th { (text(language, "col_risk_entity")) }
                            th { (text(language, "col_risk_value")) }
                            th { (text(language, "col_risk_used")) }
                            th { (text(language, "col_risk_dropped")) }
                        }
                    }
                    tbody {
                        @for entity in &list.entities { (risk_row(language, entity)) }
                    }
                }
            }
        },
    )
}


pub fn risk_entity_page(language: Language, csrf: &str, detail: &RiskDetailView) -> Markup {
    let entity = &detail.entity;
    layout(
        language,
        "title_risk_entity",
        Some(csrf),
        html! {
            h1 { (text(language, "title_risk_entity")) " " (entity.id) }
            (risk_banner(language, &detail.truncated))
            dl {
                dt { (text(language, "col_kind")) }
                dd { (text(language, risk_kind_key(&entity.kind))) }
                dt { (text(language, "col_risk_value")) }
                dd { (risk_bar(entity.value)) }
                dt { (text(language, "col_risk_used")) }
                dd { (entity.contributions_used) }
                dt { (text(language, "col_risk_dropped")) }
                dd { (entity.contributions_dropped) }
                dt { (text(language, "risk_computed")) }
                dd { (format_time(language, detail.computed_at)) }
            }
            (go("/risk", text(language, "risk_back")))
        },
    )
}


/// A fixed key per expiry state of the API; any other value is the fixed "unknown" text.
pub fn cert_expiry_key(expiry: &str) -> &'static str {
    match expiry {
        "expired" => "cert_expired",
        "near" => "cert_near",
        "ok" => "cert_ok",
        _ => "unknown",
    }
}


pub fn cert_filter_key(filter: &str) -> &'static str {
    match filter {
        "30" => "certs_filter_30",
        "90" => "certs_filter_90",
        _ => "certs_filter_all",
    }
}


/// At most `shown` DNS names, each clipped, then the count of the others.
pub fn cert_dns_names(language: Language, names: &[String], shown: usize) -> Markup {
    let hidden = names.len().saturating_sub(shown);
    html! {
        @for name in names.iter().take(shown) {
            div { (clip_dns(language, name, MAX_FIELD_CHARS)) }
        }
        @if hidden > 0 {
            div { (text(language, "cert_dns_more").replace("{count}", &hidden.to_string())) }
        }
    }
}


pub fn cert_key_text(language: Language, cert: &CertView) -> String {
    let kind = clip_identity(language, &cert.key_type, MAX_FIELD_CHARS);
    cert.key_bits.map_or(kind.clone(), |bits| format!("{kind} {bits}"))
}


pub fn cert_row(language: Language, cert: &CertView) -> Markup {
    if valid_id(&cert.fingerprint) {
        html! {
            tr {
                td { (go(&format!("/certificates/{}", cert.fingerprint), &cert.fingerprint)) }
                td { (clip_identity(language, &cert.subject, MAX_FIELD_CHARS)) }
                td { (clip_identity(language, &cert.issuer, MAX_FIELD_CHARS)) }
                td { (cert_dns_names(language, &cert.dns_names, MAX_ROW_DNS_NAMES)) }
                td { (clip(language, &cert.not_after, MAX_FIELD_CHARS)) }
                td { (text(language, cert_expiry_key(&cert.expiry))) }
                td { (cert_key_text(language, cert)) }
            }
        }
    } else {
        html! {
            tr { td colspan="7" { (text(language, "certs_unreadable")) } }
        }
    }
}


pub fn cert_filter_forms(language: Language) -> Markup {
    html! {
        @for filter in CERT_FILTERS {
            form method="get" action="/certificates" class="go" {
                input type="hidden" name="expiring" value=(filter);
                button type="submit" { (text(language, cert_filter_key(filter))) }
            }
        }
    }
}


pub fn certs_page(language: Language, csrf: &str, list: &CertListView, filter: &str) -> Markup {
    layout(
        language,
        "title_certs",
        Some(csrf),
        html! {
            h1 { (text(language, "title_certs")) }
            (cert_filter_forms(language))
            @if list.skipped > 0 {
                div class="notice" { (text(language, "certs_skipped").replace("{count}", &list.skipped.to_string())) }
            }
            @if list.items.is_empty() {
                div { (text(language, "certs_empty")) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_fingerprint")) }
                            th { (text(language, "col_subject")) }
                            th { (text(language, "col_issuer")) }
                            th { (text(language, "col_dns")) }
                            th { (text(language, "col_not_after")) }
                            th { (text(language, "col_expiry")) }
                            th { (text(language, "col_key")) }
                        }
                    }
                    tbody {
                        @for cert in &list.items { (cert_row(language, cert)) }
                    }
                }
            }
            @if let Some(cursor) = &list.next_cursor {
                form method="get" action="/certificates" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    input type="hidden" name="expiring" value=(filter);
                    button type="submit" { (text(language, "certs_next")) }
                }
            }
        },
    )
}


pub fn cert_page(language: Language, csrf: &str, detail: &CertDetailView) -> Markup {
    let cert = &detail.cert;
    let self_signed = if cert.self_signed { "cert_yes" } else { "cert_no" };
    layout(
        language,
        "title_cert",
        Some(csrf),
        html! {
            h1 { (text(language, "title_cert")) " " (cert.fingerprint) }
            dl {
                dt { (text(language, "col_subject")) }
                dd { (clip_identity(language, &cert.subject, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_issuer")) }
                dd { (clip_identity(language, &cert.issuer, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_dns")) }
                dd { (cert_dns_names(language, &cert.dns_names, MAX_DETAIL_DNS_NAMES)) }
                dt { (text(language, "col_not_before")) }
                dd { (clip(language, &cert.not_before, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_not_after")) }
                dd { (clip(language, &cert.not_after, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_expiry")) }
                dd { (text(language, cert_expiry_key(&cert.expiry))) }
                dt { (text(language, "col_key")) }
                dd { (cert_key_text(language, cert)) }
                dt { (text(language, "cert_self_signed")) }
                dd { (text(language, self_signed)) }
                dt { (text(language, "col_first_seen")) }
                dd { (clip(language, &cert.first_seen, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_last_seen")) }
                dd { (clip(language, &cert.last_seen, MAX_FIELD_CHARS)) }
            }
            h2 { (text(language, "cert_sightings")) }
            @if detail.sightings_skipped > 0 {
                div class="notice" { (text(language, "cert_sightings_skipped").replace("{count}", &detail.sightings_skipped.to_string())) }
            }
            @if detail.sightings_truncated {
                div class="notice" { (text(language, "cert_sightings_truncated")) }
            }
            table {
                thead {
                    tr {
                        th { (text(language, "col_sighting_kind")) }
                        th { (text(language, "col_reference")) }
                        th { (text(language, "col_last_seen")) }
                    }
                }
                tbody {
                    @for sighting in &detail.sightings {
                        tr {
                            td { (clip_identity(language, &sighting.kind, MAX_FIELD_CHARS)) }
                            td { (clip_identity(language, &sighting.reference, MAX_FIELD_CHARS)) }
                            td { (clip(language, &sighting.last_seen, MAX_FIELD_CHARS)) }
                        }
                    }
                }
            }
            (go("/certificates", text(language, "cert_back")))
        },
    )
}


pub const MAX_YEAR: i32 = 9999;


/// A window end as UTC RFC 3339, `None` unless it parses and the UTC date stays within years 0 to 9999.
pub fn window_time(value: &str) -> Option<String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|moment| moment.checked_to_offset(UtcOffset::UTC))
        .filter(|utc| (0..=MAX_YEAR).contains(&utc.year()))
        .and_then(|utc| utc.format(&Rfc3339).ok())
}


pub fn finding_row(language: Language, finding: &FindingView) -> Markup {
    let start = window_time(&finding.window_start);
    let end = window_time(&finding.window_end);
    match (valid_pack_id(&finding.pack_id), start, end) {
        (true, Some(from), Some(until)) => html! {
            tr {
                td { (finding.pack_id) }
                td { (from) }
                td { (until) }
                td { (finding.matches) }
                td { (finding.max_matches) }
            }
        },
        _ => html! {
            tr { td colspan="5" { (text(language, "hunts_unreadable")) } }
        },
    }
}


pub fn hunts_notices(language: Language, list: &FindingsView) -> Markup {
    let oversized_key = if list.oversized.capped {
        "hunts_oversized_capped"
    } else {
        "hunts_oversized"
    };
    let oversized_one_key = if list.oversized.capped {
        "hunts_oversized_capped_one"
    } else {
        "hunts_oversized_one"
    };
    html! {
        @if list.skipped > 0 {
            div class="notice" { (counted_notice(language, "hunts_skipped_one", "hunts_skipped", list.skipped)) }
        }
        @if list.oversized.count > 0 {
            div class="notice" { (counted_notice(language, oversized_one_key, oversized_key, list.oversized.count.unsigned_abs())) }
        }
    }
}


/// The singular text for a count of one, else the plural text with its `{count}`.
pub fn counted_notice(language: Language, one_key: &str, many_key: &str, count: u64) -> String {
    let key = if count == 1 { one_key } else { many_key };
    text(language, key).replace("{count}", &count.to_string())
}


pub fn hunts_page(language: Language, csrf: &str, list: &FindingsView) -> Markup {
    layout(
        language,
        "title_hunts",
        Some(csrf),
        html! {
            h1 { (text(language, "title_hunts")) }
            (hunts_notices(language, list))
            @if list.items.is_empty() {
                div { (text(language, if list.skipped > 0 { "hunts_no_readable" } else { "hunts_empty" })) }
            } @else {
                table {
                    thead {
                        tr {
                            th { (text(language, "col_pack")) }
                            th { (text(language, "col_window_start")) }
                            th { (text(language, "col_window_end")) }
                            th { (text(language, "col_matches")) }
                            th { (text(language, "col_max_matches")) }
                        }
                    }
                    tbody {
                        @for finding in &list.items { (finding_row(language, finding)) }
                    }
                }
            }
            @if let Some(cursor) = &list.next_cursor {
                form method="get" action="/hunts" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    button type="submit" { (text(language, "hunts_next")) }
                }
            }
        },
    )
}


pub const NO_TIME: &str = "-";


pub const STATE_LIST_COLUMNS: u32 = 6;


pub const STATE_ASSET_COLUMNS: u32 = 5;


/// The text key of one of the four stored verdicts, `None` for anything else.
pub fn verdict_key(verdict: &str) -> Option<&'static str> {
    match verdict {
        "fail" => Some("verdict_fail"),
        "error" => Some("verdict_error"),
        "excepted" => Some("verdict_excepted"),
        "pass" => Some("verdict_pass"),
        _other => None,
    }
}


/// The verdict key and both times as UTC text, `None` unless every field is inside its grammar.
pub fn readable_state(state: &StateView) -> Option<(&'static str, String, String)> {
    let first_failed = state.first_failed.as_deref().map_or(Some(NO_TIME.to_owned()), window_time);
    let last_seen = window_time(&state.last_seen);
    let identity = valid_state_id(&state.baseline) && valid_state_id(&state.control) && valid_state_asset(&state.asset);
    identity
        .then(|| verdict_key(&state.verdict))
        .flatten()
        .zip(first_failed)
        .zip(last_seen)
        .map(|((key, first), last)| (key, first, last))
}


/// One row; `only_asset` is the asset of a detail page, where a row of another asset is refused alone.
pub fn state_row(language: Language, state: &StateView, only_asset: Option<&str>) -> Markup {
    let shown = readable_state(state).filter(|_| only_asset.is_none_or(|asset| asset == state.asset));
    match shown {
        Some((key, first_failed, last_seen)) => html! {
            tr {
                td { (state.baseline) }
                td { (state.control) }
                @if only_asset.is_none() {
                    td { (go(&format!("/compliance/{}", encode_asset_id(&state.asset)), &state.asset)) }
                }
                td { (text(language, key)) }
                td { (first_failed) }
                td { (last_seen) }
            }
        },
        None => html! {
            tr { td colspan=(if only_asset.is_none() { STATE_LIST_COLUMNS } else { STATE_ASSET_COLUMNS }) { (text(language, "compliance_unreadable")) } }
        },
    }
}


pub fn state_head(language: Language, with_asset: bool) -> Markup {
    html! {
        thead {
            tr {
                th { (text(language, "col_baseline")) }
                th { (text(language, "col_control")) }
                @if with_asset {
                    th { (text(language, "col_asset")) }
                }
                th { (text(language, "col_verdict")) }
                th { (text(language, "col_first_failed")) }
                th { (text(language, "col_last_seen")) }
            }
        }
    }
}


pub fn state_filter_form(language: Language, verdict: &str, baseline: Option<&str>) -> Markup {
    html! {
        form method="get" action="/compliance" {
            label {
                (text(language, "compliance_verdict_label")) " "
                select name="verdict" {
                    @for option in STATE_VERDICTS.iter().chain([&VERDICT_ALL]) {
                        option value=(option) selected[*option == verdict] {
                            (text(language, verdict_key(option).unwrap_or("verdict_all")))
                        }
                    }
                }
            }
            label {
                (text(language, "compliance_baseline_label")) " "
                input type="text" name="baseline" maxlength=(MAX_STATE_ID_CHARS) value=(baseline.unwrap_or(""));
            }
            button type="submit" { (text(language, "compliance_filter")) }
        }
    }
}


pub fn compliance_page(language: Language, csrf: &str, list: &StateListView, verdict: &str, baseline: Option<&str>) -> Markup {
    layout(
        language,
        "title_compliance",
        Some(csrf),
        html! {
            h1 { (text(language, "title_compliance")) }
            (state_filter_form(language, verdict, baseline))
            @if list.skipped > 0 {
                div class="notice" { (counted_notice(language, "compliance_skipped_one", "compliance_skipped", list.skipped)) }
            }
            @if list.items.is_empty() {
                div { (text(language, if list.skipped > 0 { "compliance_no_readable" } else { "compliance_empty" })) }
            } @else {
                table {
                    (state_head(language, true))
                    tbody {
                        @for state in &list.items { (state_row(language, state, None)) }
                    }
                }
            }
            @if let Some(cursor) = &list.next_cursor {
                form method="get" action="/compliance" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    input type="hidden" name="verdict" value=(verdict);
                    @if let Some(name) = baseline {
                        input type="hidden" name="baseline" value=(name);
                    }
                    button type="submit" { (text(language, "compliance_next")) }
                }
            }
        },
    )
}


pub fn compliance_asset_page(language: Language, csrf: &str, asset: &str, detail: &StateAssetView) -> Markup {
    layout(
        language,
        "title_compliance_asset",
        Some(csrf),
        html! {
            h1 { (text(language, "title_compliance_asset")) " " (asset) }
            @if detail.skipped > 0 {
                div class="notice" { (counted_notice(language, "compliance_skipped_one", "compliance_skipped", detail.skipped)) }
            }
            @if detail.truncated {
                div class="notice" { (text(language, "compliance_truncated")) }
            }
            @if detail.items.is_empty() {
                div { (text(language, if detail.skipped > 0 { "compliance_no_readable" } else { "compliance_empty" })) }
            } @else {
                table {
                    (state_head(language, false))
                    tbody {
                        @for state in &detail.items { (state_row(language, state, Some(asset))) }
                    }
                }
            }
            (go("/compliance", text(language, "compliance_back")))
        },
    )
}


pub const VULN_LIST_COLUMNS: u32 = 12;


pub const VULN_ASSET_COLUMNS: u32 = 11;


/// Both scores and both times as text, `None` unless every text is inside the store's grammar and both scores inside their ranges.
pub fn readable_vuln(view: &VulnView) -> Option<(String, String, String, String)> {
    let texts_fit = valid_vuln_asset(&view.asset)
        && [&view.ecosystem, &view.package, &view.record_id, &view.installed_version]
            .iter()
            .all(|value| valid_vuln_field(value))
        && view.fixed_version.as_deref().is_none_or(valid_vuln_field);
    let cvss = vuln_score(&view.cvss, VULN_CVSS_MAX).map(|score| format!("{score:.1}"));
    let epss = vuln_score(&view.epss, VULN_EPSS_MAX).map(|score| format!("{score:.3}"));
    texts_fit
        .then_some(cvss)
        .flatten()
        .zip(epss)
        .zip(window_time(&view.first_seen))
        .zip(window_time(&view.last_seen))
        .map(|(((cvss_text, epss_text), first), last)| (cvss_text, epss_text, first, last))
}


/// One row; `only_asset` is the asset of a detail page, where a row of another asset is refused alone.
pub fn vuln_row(language: Language, view: &VulnView, only_asset: Option<&str>) -> Markup {
    let shown = readable_vuln(view).filter(|_| only_asset.is_none_or(|asset| asset == view.asset));
    match shown {
        Some((cvss, epss, first_seen, last_seen)) => html! {
            tr {
                @if only_asset.is_none() {
                    td { (go(&format!("/vulnerabilities/{}", encode_asset_id(&view.asset)), &view.asset)) }
                }
                td { (view.ecosystem) }
                td { (view.package) }
                td { (view.record_id) }
                td { (view.installed_version) }
                td { (view.fixed_version.as_deref().unwrap_or(NO_TIME)) }
                td { (cvss) }
                td { (epss) }
                td {
                    @if view.kev {
                        strong class="badge" { (text(language, "vulns_kev")) }
                    }
                }
                td { (view.priority) }
                td { (first_seen) }
                td { (last_seen) }
            }
        },
        None => html! {
            tr { td colspan=(if only_asset.is_none() { VULN_LIST_COLUMNS } else { VULN_ASSET_COLUMNS }) { (text(language, "vulns_unreadable")) } }
        },
    }
}


pub fn vuln_head(language: Language, with_asset: bool) -> Markup {
    html! {
        thead {
            tr {
                @if with_asset {
                    th { (text(language, "col_asset")) }
                }
                th { (text(language, "col_ecosystem")) }
                th { (text(language, "col_package")) }
                th { (text(language, "col_record")) }
                th { (text(language, "col_installed")) }
                th { (text(language, "col_fixed")) }
                th { (text(language, "col_cvss")) }
                th { (text(language, "col_epss")) }
                th { (text(language, "vulns_kev")) }
                th { (text(language, "col_priority")) }
                th { (text(language, "col_first_seen")) }
                th { (text(language, "col_last_seen")) }
            }
        }
    }
}


pub fn vulns_page(language: Language, csrf: &str, list: &VulnListView) -> Markup {
    layout(
        language,
        "title_vulns",
        Some(csrf),
        html! {
            h1 { (text(language, "title_vulns")) }
            @if list.skipped > 0 {
                div class="notice" { (counted_notice(language, "vulns_skipped_one", "vulns_skipped", list.skipped)) }
            }
            @if list.items.is_empty() {
                div { (text(language, if list.skipped > 0 { "vulns_no_readable" } else { "vulns_empty" })) }
            } @else {
                table {
                    (vuln_head(language, true))
                    tbody {
                        @for view in &list.items { (vuln_row(language, view, None)) }
                    }
                }
            }
            @if let Some(cursor) = &list.next_cursor {
                form method="get" action="/vulnerabilities" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    button type="submit" { (text(language, "vulns_next")) }
                }
            }
        },
    )
}


pub fn vuln_asset_page(language: Language, csrf: &str, asset: &str, detail: &VulnAssetView) -> Markup {
    layout(
        language,
        "title_vuln_asset",
        Some(csrf),
        html! {
            h1 { (text(language, "title_vuln_asset")) " " (asset) }
            @if detail.skipped > 0 {
                div class="notice" { (counted_notice(language, "vulns_skipped_one", "vulns_skipped", detail.skipped)) }
            }
            @if detail.truncated {
                div class="notice" { (text(language, "vulns_truncated")) }
            }
            @if detail.items.is_empty() {
                div { (text(language, if detail.skipped > 0 { "vulns_no_readable" } else { "vulns_empty" })) }
            } @else {
                table {
                    (vuln_head(language, false))
                    tbody {
                        @for view in &detail.items { (vuln_row(language, view, Some(asset))) }
                    }
                }
            }
            (go("/vulnerabilities", text(language, "vulns_back")))
        },
    )
}


pub const ONCALL_COLUMNS: u32 = 8;


/// The text key of one of the four phases the oncall API names, `None` for anything else.
pub fn oncall_state_key(state: &str) -> Option<&'static str> {
    match state {
        "open" => Some("oncall_state_open"),
        "acknowledged" => Some("oncall_state_acknowledged"),
        "escalated" => Some("oncall_state_escalated"),
        "resolved" => Some("oncall_state_resolved"),
        _other => None,
    }
}


/// The state key and the three times as UTC text, `None` unless the fingerprint, state, counters and times are all inside their rules.
pub fn readable_oncall(alert: &OncallAlertView) -> Option<(&'static str, String, String, String)> {
    let acknowledged = alert.acknowledged_at.as_deref().map_or(Some(NO_TIME.to_owned()), window_time);
    let resolved = alert.resolved_at.as_deref().map_or(Some(NO_TIME.to_owned()), window_time);
    let opened = window_time(&alert.opened_at);
    let sound = valid_oncall_text(&alert.fingerprint, MAX_ONCALL_FINGERPRINT_BYTES) && alert.id >= 0 && alert.occurrences >= 0;
    sound
        .then(|| oncall_state_key(&alert.state))
        .flatten()
        .zip(opened)
        .zip(acknowledged)
        .zip(resolved)
        .map(|(((key, opened_at), acknowledged_at), resolved_at)| (key, opened_at, acknowledged_at, resolved_at))
}


/// One row; the id is a link only on the list.
pub fn oncall_row(language: Language, alert: &OncallAlertView, linked: bool) -> Markup {
    match readable_oncall(alert) {
        Some((key, opened, acknowledged, resolved)) => html! {
            tr {
                td {
                    @if linked {
                        (go(&format!("/oncall/{}", alert.id), &alert.id.to_string()))
                    } @else {
                        (alert.id)
                    }
                }
                td { (alert.fingerprint) }
                td { (text(language, key)) }
                td { (alert.level) }
                td { (alert.occurrences) }
                td { (opened) }
                td { (acknowledged) }
                td { (resolved) }
            }
        },
        None => html! {
            tr { td colspan=(ONCALL_COLUMNS) { (text(language, "oncall_unreadable")) } }
        },
    }
}


pub fn oncall_head(language: Language) -> Markup {
    html! {
        thead {
            tr {
                th { (text(language, "col_oncall_id")) }
                th { (text(language, "col_fingerprint")) }
                th { (text(language, "col_status")) }
                th { (text(language, "col_level")) }
                th { (text(language, "col_occurrences")) }
                th { (text(language, "col_opened_at")) }
                th { (text(language, "col_acknowledged_at")) }
                th { (text(language, "col_resolved_at")) }
            }
        }
    }
}


pub fn oncall_page(language: Language, csrf: &str, list: &OncallListView) -> Markup {
    layout(
        language,
        "title_oncall",
        Some(csrf),
        html! {
            h1 { (text(language, "title_oncall")) }
            @if list.skipped > 0 {
                div class="notice" { (counted_notice(language, "oncall_skipped_one", "oncall_skipped", list.skipped)) }
            }
            @if list.items.is_empty() {
                div { (text(language, if list.skipped > 0 { "oncall_no_readable" } else { "oncall_empty" })) }
            } @else {
                table {
                    (oncall_head(language))
                    tbody {
                        @for alert in &list.items { (oncall_row(language, alert, true)) }
                    }
                }
            }
        },
    )
}


pub fn oncall_alert_page(language: Language, csrf: &str, alert: &OncallAlertView) -> Markup {
    layout(
        language,
        "title_oncall_alert",
        Some(csrf),
        html! {
            h1 { (text(language, "title_oncall_alert")) " " (alert.id) }
            table {
                (oncall_head(language))
                tbody { (oncall_row(language, alert, false)) }
            }
            (go("/oncall", text(language, "oncall_back")))
        },
    )
}


pub const DHCP_COLUMNS: u32 = 7;


/// What one lease row prints, every part already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableLease {
    pub address: String,
    pub mac: String,
    pub hostname: String,
    pub hostname_refused: bool,
    pub starts: String,
    pub ends: String,
}


/// `None` unless the address parses, the MAC and the hostname are inside the store's grammars (an absent one is `-`) and both times are RFC 3339.
pub fn readable_lease(view: &LeaseView) -> Option<ReadableLease> {
    let address = parse_dhcp_address(Some(&view.address)).map(|found| found.to_string());
    let mac = view.mac.as_deref().map_or(Some(NO_TIME.to_owned()), |found| parse_dhcp_mac(Some(found)));
    let hostname = view
        .hostname
        .as_deref()
        .map_or(Some(NO_TIME.to_owned()), |found| valid_dhcp_hostname(found).then(|| found.to_owned()));
    address
        .zip(mac)
        .zip(hostname)
        .zip(window_time(&view.starts))
        .zip(window_time(&view.ends))
        .map(|((((address_text, mac_text), hostname_text), starts), ends)| ReadableLease {
            address: address_text,
            mac: mac_text,
            hostname: hostname_text,
            hostname_refused: view.hostname_refused,
            starts,
            ends,
        })
}


pub fn lease_row(language: Language, view: &LeaseView) -> Markup {
    match readable_lease(view) {
        Some(lease) => html! {
            tr {
                td { (lease.address) }
                td { (lease.mac) }
                td {
                    @if lease.hostname_refused {
                        (text(language, "dhcp_hostname_refused"))
                    } @else {
                        (lease.hostname)
                    }
                }
                td { (lease.starts) }
                td { (lease.ends) }
                td { (text(language, dhcp_action_key(&view.action))) }
                td { (view.subnet_id) }
            }
        },
        None => html! {
            tr { td colspan=(DHCP_COLUMNS) { (text(language, "dhcp_unreadable")) } }
        },
    }
}


pub fn lease_head(language: Language) -> Markup {
    html! {
        thead {
            tr {
                th { (text(language, "col_address")) }
                th { (text(language, "col_mac")) }
                th { (text(language, "col_hostname")) }
                th { (text(language, "col_starts")) }
                th { (text(language, "col_ends")) }
                th { (text(language, "col_action")) }
                th { (text(language, "col_subnet")) }
            }
        }
    }
}


pub fn dhcp_field(language: Language, name: &str, label_key: &str) -> Markup {
    html! {
        label { (text(language, label_key)) " " input type="text" name=(name) required; }
    }
}


pub fn dhcp_result(language: Language, found: &LookupView) -> Markup {
    html! {
        @if found.skipped > 0 {
            div class="notice" { (counted_notice(language, "dhcp_skipped_one", "dhcp_skipped", found.skipped)) }
        }
        @if found.truncated {
            div class="notice" { (text(language, "dhcp_truncated")) }
        }
        @if found.intervals.is_empty() {
            div { (text(language, if found.skipped > 0 { "dhcp_no_readable" } else { "dhcp_empty" })) }
        } @else {
            table {
                (lease_head(language))
                tbody {
                    @for view in &found.intervals { (lease_row(language, view)) }
                }
            }
        }
    }
}


pub fn dhcp_page(language: Language, csrf: &str, found: Option<&LookupView>) -> Markup {
    layout(
        language,
        "title_dhcp",
        Some(csrf),
        html! {
            h1 { (text(language, "title_dhcp")) }
            h2 { (text(language, "dhcp_at_title")) }
            form method="get" action="/dhcp" {
                (dhcp_field(language, "address", "label_address"))
                (dhcp_field(language, "at", "label_at"))
                button type="submit" { (text(language, "dhcp_search")) }
            }
            h2 { (text(language, "dhcp_mac_title")) }
            form method="get" action="/dhcp" {
                (dhcp_field(language, "mac", "label_mac"))
                (dhcp_field(language, "from", "label_from"))
                (dhcp_field(language, "to", "label_to"))
                button type="submit" { (text(language, "dhcp_search")) }
            }
            @if let Some(result) = found {
                (dhcp_result(language, result))
            }
        },
    )
}


pub const MICROS_PER_SECOND: i64 = 1_000_000;


/// The run's counts as `(label key, value)` rows, in the order they are shown.
pub fn posture_counts(run: &PostureRunView) -> Vec<(&'static str, u64)> {
    vec![
        ("posture_items", run.items),
        ("posture_unparsable", run.unparsable),
        ("posture_bad_field", run.bad_field),
        ("posture_duplicate", run.duplicate),
        ("posture_foreign", run.foreign_account),
        ("posture_refused", run.refused_items),
        ("posture_refused_pass", run.refused_pass),
        ("posture_refused_muted", run.refused_muted),
        ("posture_refused_manual", run.refused_manual),
        ("posture_refused_fail", run.refused_fail),
        ("posture_store_refused", run.store_refused),
    ]
}


/// A microsecond time as UTC RFC 3339, an absent one as `-`.
pub fn posture_time(language: Language, micros: Option<i64>) -> String {
    micros.map_or_else(|| NO_TIME.to_owned(), |found| format_time(language, found.div_euclid(MICROS_PER_SECOND)))
}


pub fn posture_header(language: Language, view: &PostureView) -> Markup {
    html! {
        @if view.unservable > 0 {
            div class="notice" { (counted_notice(language, "posture_unservable_one", "posture_unservable", view.unservable)) }
        }
        @match &view.run {
            Some(run) => {
                @if run.refusal_pending {
                    div class="notice" { (text(language, "posture_pending")) }
                }
                dl {
                    dt { (text(language, "posture_finished")) }
                    dd { (posture_time(language, run.finished_micros)) }
                    dt { (text(language, "posture_refused_at")) }
                    dd { (posture_time(language, run.refused_micros)) }
                    @for (key, count) in posture_counts(run) {
                        dt { (text(language, key)) }
                        dd { (count) }
                    }
                }
            }
            None => {
                div { (text(language, "posture_none")) }
            }
        }
    }
}


/// A cut count as its own marker, never part of the (escaped) text it follows.
pub fn posture_cut(language: Language, cut: u64) -> Markup {
    html! {
        @if cut > 0 {
            " "
            span class="notice" { (text(language, "posture_cut").replace("{count}", &cut.to_string())) }
        }
    }
}


pub fn posture_row(language: Language, finding: &PostureFindingView) -> Markup {
    html! {
        tr {
            td { (clip_identity(language, &finding.check_id, MAX_FIELD_CHARS)) }
            td { (text(language, posture_severity_key(&finding.severity))) }
            td { (text(language, posture_status_key(&finding.status))) }
            td { (clip_identity(language, &finding.resource_uid, MAX_FIELD_CHARS)) }
            td { (format_time(language, finding.time_unix)) }
            td { (clip(language, &finding.title, MAX_FIELD_CHARS)) (posture_cut(language, finding.title_cut)) }
            td { (clip(language, &finding.detail, MAX_FIELD_CHARS)) (posture_cut(language, finding.detail_cut)) }
        }
    }
}


pub fn posture_head(language: Language) -> Markup {
    html! {
        thead {
            tr {
                th { (text(language, "col_check")) }
                th { (text(language, "col_severity")) }
                th { (text(language, "col_status")) }
                th { (text(language, "col_resource")) }
                th { (text(language, "col_time")) }
                th { (text(language, "col_finding_title")) }
                th { (text(language, "col_finding_detail")) }
            }
        }
    }
}


pub fn posture_form_page(language: Language, csrf: &str) -> Markup {
    layout(
        language,
        "title_posture",
        Some(csrf),
        html! {
            h1 { (text(language, "title_posture")) }
            form method="get" action="/posture" {
                label { (text(language, "label_account")) " " input type="text" name="account" required; }
                button type="submit" { (text(language, "posture_search")) }
            }
        },
    )
}


pub fn posture_page(language: Language, csrf: &str, account: &str, view: &PostureView) -> Markup {
    layout(
        language,
        "title_posture",
        Some(csrf),
        html! {
            h1 { (text(language, "title_posture")) " " (account) }
            (posture_header(language, view))
            @if view.run.is_some() {
                @if view.items.is_empty() {
                    div { (text(language, "posture_empty")) }
                } @else {
                    table {
                        (posture_head(language))
                        tbody {
                            @for finding in &view.items { (posture_row(language, finding)) }
                        }
                    }
                }
            }
            @if let Some(cursor) = &view.next_cursor {
                form method="get" action=(format!("/posture/{}", encode_asset_id(account))) class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    button type="submit" { (text(language, "posture_next")) }
                }
            }
            (go("/posture", text(language, "posture_back")))
        },
    )
}


/// The 409 page: the run was replaced between two pages, so the cursor is dead; a link restarts from the first page.
pub fn posture_changed_page(language: Language, csrf: &str, account: &str) -> Markup {
    layout(
        language,
        "title_posture",
        Some(csrf),
        html! {
            h1 { (text(language, "title_posture")) }
            div class="notice" { (text(language, RUN_CHANGED_KEY)) }
            (go(&format!("/posture/{}", encode_asset_id(account)), text(language, "posture_first")))
        },
    )
}


/// The named page for a findings page over the body cap: our text and a link to the first page.
pub fn posture_too_large_page(language: Language, csrf: &str, account: &str) -> Markup {
    layout(
        language,
        "title_posture",
        Some(csrf),
        html! {
            h1 { (text(language, "title_posture")) }
            div class="notice" { (text(language, "posture_too_large")) }
            (go(&format!("/posture/{}", encode_asset_id(account)), text(language, "posture_first")))
        },
    )
}


pub const SHELL_COLUMNS: u32 = 7;


pub const SHELL_FIELD_ROWS: [&str; 10] = [
    "col_session",
    "col_requester",
    "col_asset",
    "col_ticket",
    "col_opened_at",
    "col_closed_at",
    "col_close_reason",
    "col_frames",
    "col_hash",
    "col_bytes",
];


/// How a closed row ended: `Some(None)` for an open one, `None` unless every closed part is present and inside its grammar.
pub fn shell_end(view: &ShellSessionView) -> Option<Option<ShellEnd>> {
    match (
        &view.closed_at,
        &view.close_reason,
        view.recording_frames,
        &view.recording_hash,
        view.recording_bytes,
    ) {
        (None, None, None, None, None) => Some(None),
        (Some(closed), Some(reason), Some(frames), Some(hash), Some(bytes)) => window_time(closed)
            .zip(shell_reason_key(reason))
            .filter(|_| frames >= MIN_SHELL_FRAMES && bytes >= 0 && valid_shell_hash(hash))
            .map(|(closed_at, reason_key)| {
                Some(ShellEnd {
                    closed_at,
                    reason_key,
                    frames,
                    hash: hash.clone(),
                    bytes,
                })
            }),
        _ => None,
    }
}


/// `None` unless the four texts are inside the register's grammars, the open time is a UTC year 0 to 9999 and the end is consistent.
pub fn readable_shell(view: &ShellSessionView) -> Option<ShellFacts> {
    let identity = valid_shell_reference(&view.session_id)
        && valid_shell_subject(&view.requester)
        && valid_shell_reference(&view.asset)
        && valid_shell_reference(&view.ticket);
    identity
        .then(|| window_time(&view.opened_at))
        .flatten()
        .zip(shell_end(view))
        .map(|(opened_at, end)| ShellFacts { opened_at, end })
}


pub fn shell_row(language: Language, view: &ShellSessionView) -> Markup {
    match readable_shell(view) {
        Some(facts) => html! {
            tr {
                td { (go(&format!("/remote-shell/{}", encode_asset_id(&view.session_id)), &view.session_id)) }
                td { (view.requester) }
                td { (view.asset) }
                td { (view.ticket) }
                td { (facts.opened_at) }
                @if let Some(end) = &facts.end {
                    td { (end.closed_at) }
                    td { (text(language, end.reason_key)) }
                } @else {
                    td { (NO_TIME) }
                    td { (text(language, "shell_still_open")) }
                }
            }
        },
        None => html! {
            tr { td colspan=(SHELL_COLUMNS) { (text(language, "shell_unreadable")) } }
        },
    }
}


pub fn shell_head(language: Language) -> Markup {
    html! {
        thead {
            tr {
                @for key in SHELL_FIELD_ROWS.iter().take(SHELL_COLUMNS as usize) {
                    th { (text(language, key)) }
                }
            }
        }
    }
}


pub fn shell_filter_form(language: Language, query: &ShellQuery) -> Markup {
    html! {
        form method="get" action="/remote-shell" {
            label {
                (text(language, "col_asset")) " "
                input type="text" name="asset" maxlength=(MAX_SHELL_REFERENCE_BYTES) value=(query.asset.as_deref().unwrap_or(""));
            }
            label {
                (text(language, "col_requester")) " "
                input type="text" name="requester" maxlength=(MAX_SHELL_SUBJECT_BYTES) value=(query.requester.as_deref().unwrap_or(""));
            }
            label {
                (text(language, "shell_open_label")) " "
                select name="open" {
                    option value="" selected[query.open.is_none()] { (text(language, "shell_open_any")) }
                    option value=(SHELL_OPEN_ONLY) selected[query.open == Some(SHELL_OPEN_ONLY)] { (text(language, "shell_open_only")) }
                }
            }
            button type="submit" { (text(language, "shell_filter")) }
        }
    }
}


pub fn shell_page(language: Language, csrf: &str, list: &ShellListView, query: &ShellQuery) -> Markup {
    layout(
        language,
        "title_shell",
        Some(csrf),
        html! {
            h1 { (text(language, "title_shell")) }
            (shell_filter_form(language, query))
            @if list.skipped > 0 {
                div class="notice" { (counted_notice(language, "shell_skipped_one", "shell_skipped", list.skipped)) }
            }
            @if list.items.is_empty() {
                div { (text(language, if list.skipped > 0 { "shell_no_readable" } else { "shell_empty" })) }
            } @else {
                table {
                    (shell_head(language))
                    tbody {
                        @for view in &list.items { (shell_row(language, view)) }
                    }
                }
            }
            @if let Some(cursor) = &list.next_cursor {
                form method="get" action="/remote-shell" class="go" {
                    input type="hidden" name="cursor" value=(cursor);
                    @if let Some(asset) = &query.asset {
                        input type="hidden" name="asset" value=(asset);
                    }
                    @if let Some(requester) = &query.requester {
                        input type="hidden" name="requester" value=(requester);
                    }
                    @if let Some(open) = query.open {
                        input type="hidden" name="open" value=(open);
                    }
                    button type="submit" { (text(language, "shell_next")) }
                }
            }
        },
    )
}


pub fn shell_detail_rows(language: Language, view: &ShellSessionView, facts: &ShellFacts) -> Markup {
    let (closed, reason, frames, hash, bytes) = match &facts.end {
        Some(end) => (
            end.closed_at.clone(),
            text(language, end.reason_key).to_owned(),
            end.frames.to_string(),
            end.hash.clone(),
            end.bytes.to_string(),
        ),
        None => (
            NO_TIME.to_owned(),
            text(language, "shell_still_open").to_owned(),
            NO_TIME.to_owned(),
            NO_TIME.to_owned(),
            NO_TIME.to_owned(),
        ),
    };
    let values = [
        view.session_id.clone(),
        view.requester.clone(),
        view.asset.clone(),
        view.ticket.clone(),
        facts.opened_at.clone(),
        closed,
        reason,
        frames,
        hash,
        bytes,
    ];
    html! {
        table {
            tbody {
                @for (key, value) in SHELL_FIELD_ROWS.iter().zip(values.iter()) {
                    tr { th { (text(language, key)) } td { (value) } }
                }
            }
        }
    }
}


pub fn shell_detail_page(language: Language, csrf: &str, view: &ShellSessionView) -> Markup {
    layout(
        language,
        "title_shell_session",
        Some(csrf),
        html! {
            h1 { (text(language, "title_shell_session")) }
            @if let Some(facts) = readable_shell(view) {
                (shell_detail_rows(language, view, &facts))
            } @else {
                div { (text(language, "shell_unreadable")) }
            }
            (go("/remote-shell", text(language, "shell_back")))
        },
    )
}
