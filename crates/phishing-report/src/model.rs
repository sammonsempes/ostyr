use serde::{Deserialize, Serialize};


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
    pub attachments_skipped: usize,
    pub urls_refused: usize,
    pub urls_dropped: usize,
    pub urls_cleaned: usize,
    pub html_refs_undecoded: usize,
    pub addresses_refused: usize,
    pub auth_refused: usize,
    pub auth_untrusted: usize,
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


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LevelInfo {
    pub level: usize,
    pub sender: Option<String>,
    pub return_path: Option<String>,
    pub subject: Option<String>,
    pub auth: AuthVerdicts,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Triage {
    pub sender: Option<String>,
    pub return_path: Option<String>,
    pub auth: AuthVerdicts,
    pub reporter_auth: Option<AuthVerdicts>,
    pub subject: Option<String>,
    pub levels: Vec<LevelInfo>,
    pub urls: Vec<UrlHit>,
    pub attachments: Vec<AttachmentInfo>,
    pub counts: Counts,
}
