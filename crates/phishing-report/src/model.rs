use serde::{Deserialize, Serialize};
use std::collections::HashSet;


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub replaced_chars: usize,
    pub text_cut: usize,
    pub scan_cut: usize,
    pub scan_lost_bytes: usize,
    pub scan_lost_part: Option<usize>,
    pub nested_refused: usize,
    pub nesting_cut: usize,
    pub messages_unopened: usize,
    pub headers_skipped: usize,
    pub parts_skipped: usize,
    pub charset_undecoded: usize,
    pub charset_mismatch: usize,
    pub attachments_skipped: usize,
    pub urls_refused: usize,
    pub urls_dropped: usize,
    pub urls_cleaned: usize,
    pub url_cap_reached: usize,
    pub url_refused_host_kept: usize,
    pub url_host_unread: usize,
    pub url_userinfo_split: usize,
    pub url_host_ambiguous: usize,
    pub html_refs_undecoded: usize,
    pub addresses_refused: usize,
    pub auth_refused: usize,
    pub auth_untrusted: usize,
    pub auth_oversized_untrusted: usize,
    pub auth_nested_ignored: usize,
    pub reporter_unverified: usize,
    pub internal_claimed: usize,
    pub claim_unreadable: usize,
    pub claim_exhausted: usize,
    pub original_uncertain: usize,
    pub pattern_failed: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthVerdicts {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
    pub reason: Option<String>,
}


impl Default for AuthVerdicts {
    fn default() -> Self {
        Self {
            spf: "unknown".to_owned(),
            dkim: "unknown".to_owned(),
            dmarc: "unknown".to_owned(),
            reason: None,
        }
    }
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReporterPolicy {
    pub internal_domains: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentInfo {
    pub level: usize,
    pub file_name: Option<String>,
    pub content_type: String,
    pub size: usize,
    pub sha256: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlHit {
    pub level: usize,
    pub url: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    Same,
    Differs(String),
    Unreadable,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Shapes {
    #[default]
    Refuse,
    Markup,
}


#[derive(Debug, Clone, Default)]
pub struct UrlIndex {
    pub shapes: Shapes,
    pub seen: HashSet<String>,
    pub hosts: Vec<String>,
    pub hosts_seen: HashSet<String>,
    pub probes: usize,
    pub probed_bytes: usize,
    pub window_bytes: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelInfo {
    pub level: usize,
    pub sender: Option<String>,
    pub return_path: Option<String>,
    pub subject: Option<String>,
    pub senders: Vec<String>,
    pub auth: AuthVerdicts,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Triage {
    pub sender: Option<String>,
    pub return_path: Option<String>,
    pub auth: AuthVerdicts,
    pub reporter_auth: Option<AuthVerdicts>,
    pub reporter: String,
    pub original_level: Option<usize>,
    pub internal_claimed: bool,
    pub original_uncertain: bool,
    pub uncertain_reasons: Vec<String>,
    pub original_source: Option<String>,
    pub senders: Vec<String>,
    pub subject: Option<String>,
    pub levels: Vec<LevelInfo>,
    pub urls: Vec<UrlHit>,
    pub refused_hosts: Vec<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub counts: Counts,
}
