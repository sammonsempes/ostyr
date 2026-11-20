use crate::api::{encode_asset_id, risk_kind, valid_asset_id, valid_case_id, valid_id, CERT_FILTERS, MAX_COMMENT_CHARS, MAX_RISK_VALUE, RISK_KINDS};
use crate::model::{
    Alert, AlertPage, AssetDetailView, AssetPageView, AssetSummaryView, CaseDetailView, CasePageView, CaseSummaryView, CertDetailView, CertListView,
    CertView, CommentView, Language, RiskDetailView, RiskEntityView, RiskListView, RiskTruncatedView,
};
use crate::strings::{
    action_key, allowed_actions, case_severity_class, case_severity_key, language_tag, resolution_key, severity_class, severity_key, status_key,
    task_status_key, text, CLOSE_ACTION, RESOLUTIONS,
};
use ecs_normalise::suricata::{is_unsafe, REPLACEMENT};
use maud::{html, Markup, DOCTYPE};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


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
form.go{display:inline;margin:0}td button,main>form.go button{color:#06c}label{display:block;margin:.5rem 0}.notice{color:#c00}dt{font-weight:bold}\
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


pub fn displayable(character: char) -> bool {
    !is_unsafe(character)
}


pub fn optional(language: Language, value: Option<&String>) -> String {
    value.map_or_else(|| text(language, "none").to_owned(), |present| clip(language, present, MAX_FIELD_CHARS))
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
            td { (optional(language, alert.host_name.as_ref())) }
            td { (optional(language, alert.user_name.as_ref())) }
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
                dt { (clip(language, name, MAX_FIELD_CHARS)) }
                dd { (display_value(language, value)) }
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
            @for id in ids.iter().take(MAX_EVENT_IDS) { li { (clip(language, id, MAX_FIELD_CHARS)) } }
        }
        @if omitted > 0 {
            div { (omitted) " " (text(language, "omitted")) }
        }
    }
}


pub fn alert_page(language: Language, csrf: &str, alert: &Alert) -> Markup {
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
                dd { (clip(language, &alert.rule_id, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_host")) }
                dd { (optional(language, alert.host_name.as_ref())) }
                dt { (text(language, "col_user")) }
                dd { (optional(language, alert.user_name.as_ref())) }
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
            td { (optional(language, case.assignee.as_ref())) }
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
            td { (clip(language, &asset.kind, MAX_FIELD_CHARS)) }
            td { (clip(language, &asset.lifecycle, MAX_FIELD_CHARS)) }
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
                dd { (clip(language, &asset.summary.kind, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_lifecycle")) }
                dd { (clip(language, &asset.summary.lifecycle, MAX_FIELD_CHARS)) }
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
                            td { (clip(language, &entry.key, MAX_FIELD_CHARS)) }
                            td { (clip(language, &entry.value, MAX_VALUE_CHARS)) }
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
                            td { (clip(language, &entry.name, MAX_FIELD_CHARS)) }
                            td { (clip(language, &entry.value, MAX_VALUE_CHARS)) }
                            td { (clip(language, &entry.source, MAX_FIELD_CHARS)) }
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
            " " (clip(language, &comment.author, MAX_FIELD_CHARS)) " " (format_time(language, comment.at))
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
                dd { (optional(language, summary.assignee.as_ref())) }
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
            div { (clip(language, name, MAX_FIELD_CHARS)) }
        }
        @if hidden > 0 {
            div { (text(language, "cert_dns_more").replace("{count}", &hidden.to_string())) }
        }
    }
}


pub fn cert_key_text(language: Language, cert: &CertView) -> String {
    let kind = clip(language, &cert.key_type, MAX_FIELD_CHARS);
    cert.key_bits.map_or(kind.clone(), |bits| format!("{kind} {bits}"))
}


pub fn cert_row(language: Language, cert: &CertView) -> Markup {
    if valid_id(&cert.fingerprint) {
        html! {
            tr {
                td { (go(&format!("/certificates/{}", cert.fingerprint), &cert.fingerprint)) }
                td { (clip(language, &cert.subject, MAX_FIELD_CHARS)) }
                td { (clip(language, &cert.issuer, MAX_FIELD_CHARS)) }
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
                dd { (clip(language, &cert.subject, MAX_FIELD_CHARS)) }
                dt { (text(language, "col_issuer")) }
                dd { (clip(language, &cert.issuer, MAX_FIELD_CHARS)) }
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
                            td { (clip(language, &sighting.kind, MAX_FIELD_CHARS)) }
                            td { (clip(language, &sighting.reference, MAX_FIELD_CHARS)) }
                            td { (clip(language, &sighting.last_seen, MAX_FIELD_CHARS)) }
                        }
                    }
                }
            }
            (go("/certificates", text(language, "cert_back")))
        },
    )
}
