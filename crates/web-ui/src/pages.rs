use crate::api::valid_case_id;
use crate::model::{Alert, AlertPage, CaseDetailView, CasePageView, CaseSummaryView, Language};
use crate::strings::{
    case_severity_class, case_severity_key, language_tag, resolution_key, severity_class, severity_key, status_key, task_status_key, text,
};
use maud::{html, Markup, DOCTYPE};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const MAX_FIELD_CHARS: usize = 256;


pub const MAX_VALUE_CHARS: usize = 512;


pub const MAX_SUMMARY_ENTRIES: usize = 64;


pub const MAX_EVENT_IDS: usize = 50;


pub const MAX_TEXT_CHARS: usize = 4096;


pub const MAX_TASKS: usize = 64;


pub const STYLESHEET: &str = "body{font-family:sans-serif;margin:0;color:#1b1f23}header{display:flex;gap:1rem;align-items:center;padding:.5rem 1rem;\
background:#1b1f23;color:#fff}header button{color:#fff;background:none;border:0;font:inherit;cursor:pointer;text-decoration:underline}\
main{padding:1rem}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ccc;padding:.4rem;text-align:left}\
.sev-low{color:#0a6}.sev-medium{color:#b80}.sev-high{color:#c30}.sev-critical{color:#c00;font-weight:bold}\
form.go{display:inline;margin:0}td button,main>form.go button{color:#06c}label{display:block;margin:.5rem 0}.notice{color:#c00}dt{font-weight:bold}";


/// Text from the API or any peer: control and bidirectional-override characters dropped, long values cut with a visible count.
pub fn clip(language: Language, value: &str, max: usize) -> String {
    let shown: String = value.chars().filter(|character| displayable(*character)).collect();
    let omitted = shown.chars().count().saturating_sub(max);
    if omitted == 0 {
        shown
    } else {
        let kept: String = shown.chars().take(max).collect();
        format!("{kept}... [{omitted} {}]", text(language, "omitted"))
    }
}


pub fn displayable(character: char) -> bool {
    !character.is_control() && !matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
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


pub fn case_page(language: Language, csrf: &str, case: &CaseDetailView) -> Markup {
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
            (go("/cases", text(language, "case_back")))
        },
    )
}
