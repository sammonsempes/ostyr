use serde::Serialize;


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub replaced_chars: usize,
    pub text_cut: usize,
    pub scan_cut: usize,
    pub nesting_cut: usize,
    pub headers_skipped: usize,
    pub parts_skipped: usize,
    pub attachments_skipped: usize,
    pub urls_refused: usize,
    pub urls_dropped: usize,
    pub addresses_refused: usize,
    pub auth_refused: usize,
    pub pattern_failed: usize,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuthVerdicts {
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentInfo {
    pub file_name: Option<String>,
    pub content_type: String,
    pub size: usize,
    pub sha256: String,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Triage {
    pub sender: Option<String>,
    pub return_path: Option<String>,
    pub auth: AuthVerdicts,
    pub subject: Option<String>,
    pub urls: Vec<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub counts: Counts,
}
