use regex::Regex;
use std::sync::LazyLock;


pub const REDACTED: &str = "[REDACTED]";


pub const PEM_PATTERN: &str = r"(?is)-----BEGIN.*?(?:-----END[^-]*-----|\z)";


pub const URL_PATTERN: &str = r"(?i)([a-z][a-z0-9+.-]*://[^\s:@/]*):\S*@";


pub const URL_REPLACEMENT: &str = "${1}:[REDACTED]@";


pub const BEARER_PATTERN: &str = r"(?i)(bearer|basic)(\s+)(?:(?:bearer|basic)\s+)*\S+";


pub const BEARER_REPLACEMENT: &str = "${1}${2}[REDACTED]";


pub const TOKEN_SCHEME_PATTERN: &str = r#"(?i)(authorization["']?\s*[:=]\s*["']?token\s+)[^\s"']+"#;


pub const TOKEN_SCHEME_REPLACEMENT: &str = "${1}[REDACTED]";


pub const JWT_PATTERN: &str = concat!(
    r"eyJ[A-Za-z0-9_-]*=*(?:",
    r"\.[A-Za-z0-9_-]*=*(?:\.[A-Za-z0-9_-]+=*){3}",
    r"|(?:\.[A-Za-z0-9_-]+=*){2})",
);


pub static PEM_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(PEM_PATTERN));


pub static URL_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(URL_PATTERN));


pub static BEARER_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(BEARER_PATTERN));


pub static TOKEN_SCHEME_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(TOKEN_SCHEME_PATTERN));


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


/// Redacts PEM blocks, URL passwords, `bearer`/`basic` credentials and JWT/JWE tokens, wherever they sit in `text`.
pub fn redact_text(text: &str) -> String {
    let without_pem = apply_rule(&PEM_RULE, text, REDACTED);
    let without_url_password = apply_rule(&URL_RULE, &without_pem, URL_REPLACEMENT);
    let without_bearer = apply_rule(&BEARER_RULE, &without_url_password, BEARER_REPLACEMENT);
    let without_token_scheme = apply_rule(&TOKEN_SCHEME_RULE, &without_bearer, TOKEN_SCHEME_REPLACEMENT);
    apply_rule(&JWT_RULE, &without_token_scheme, REDACTED)
}
