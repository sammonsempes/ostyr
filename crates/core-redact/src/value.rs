use percent_encoding::percent_decode_str;
use regex::Regex;
use std::sync::LazyLock;


pub const REDACTED: &str = "[REDACTED]";


pub const PEM_PATTERN: &str = r"(?is)-----BEGIN.*?(?:-----END[^-]*-----|\z)";


pub const URL_PATTERN: &str = r"(?i)([a-z][a-z0-9+.-]*://[^\s:@/]*):\S*@";


pub const URL_REPLACEMENT: &str = "${1}:[REDACTED]@";


pub const AUTH_PATTERN: &str = r#"(?i)((?:proxy-authorization|authorization|x-api-key|x-auth-token)(?:\\*["'])?\s*[:=]\s*)[^\n]*"#;


pub const SCHEME_PATTERN: &str = r"(?i)(bearer|basic|token|digest|negotiate|ntlm)([\s:=]+)[^\n]*";


pub const REST_REPLACEMENT: &str = "${1}[REDACTED]";


pub const SCHEME_REPLACEMENT: &str = "${1}${2}[REDACTED]";


pub const JWT_PATTERN: &str = concat!(
    r"eyJ[A-Za-z0-9_-]*=*(?:",
    r"\.[A-Za-z0-9_-]*=*(?:\.[A-Za-z0-9_-]+=*){3}",
    r"|(?:\.[A-Za-z0-9_-]+=*){2})",
);


pub static PEM_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(PEM_PATTERN));


pub static URL_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(URL_PATTERN));


pub static AUTH_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(AUTH_PATTERN));


pub static SCHEME_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(SCHEME_PATTERN));


pub static JWT_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(JWT_PATTERN));


/// Replaces every match; a pattern that failed to compile redacts the whole text (fail closed).
pub fn apply_rule(compiled: &Result<Regex, regex::Error>, text: &str, replacement: &str) -> String {
    match compiled {
        Ok(regex) => regex.replace_all(text, replacement).into_owned(),
        Err(error) => {
            tracing::error!(%error, "redaction pattern did not compile, redacting the whole value");
            REDACTED.to_owned()
        }
    }
}


/// Applies every rule to `text` as it is written.
pub fn redact_rules(text: &str) -> String {
    let without_pem = apply_rule(&PEM_RULE, text, REDACTED);
    let without_url_password = apply_rule(&URL_RULE, &without_pem, URL_REPLACEMENT);
    let without_scheme = apply_rule(&SCHEME_RULE, &without_url_password, SCHEME_REPLACEMENT);
    let without_authorization = apply_rule(&AUTH_RULE, &without_scheme, REST_REPLACEMENT);
    apply_rule(&JWT_RULE, &without_authorization, REDACTED)
}


/// Redacts credentials anywhere in `text`; the whole text goes when only its percent-decoded copy holds one.
pub fn redact_text(text: &str) -> String {
    let decoded = percent_decode_str(text).decode_utf8_lossy();
    if decoded != text && redact_rules(&decoded) != decoded {
        REDACTED.to_owned()
    } else {
        redact_rules(text)
    }
}
