use crate::limits::{
    CHROMIUM_ID_CHARS, FIREFOX_DOMAIN_MAX, FIREFOX_GUID_CHARS, FIREFOX_GUID_GROUPS, FIREFOX_LOCAL_MAX, HTTPS_PREFIX, MAX_UPDATE_URL_BYTES,
};


pub fn is_chromium_id(text: &str) -> bool {
    text.len() == CHROMIUM_ID_CHARS && text.chars().all(|character| matches!(character, 'a'..='p'))
}


pub fn is_firefox_guid(text: &str) -> bool {
    let inner = text.strip_prefix('{').and_then(|rest| rest.strip_suffix('}'));
    let groups: Vec<&str> = inner.map_or_else(Vec::new, |body| body.split('-').collect());
    let lengths: Vec<usize> = groups.iter().map(|group| group.len()).collect();
    text.len() == FIREFOX_GUID_CHARS
        && lengths == FIREFOX_GUID_GROUPS
        && groups.iter().all(|group| group.chars().all(|character| character.is_ascii_hexdigit()))
}


pub fn is_firefox_local(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-')
}


pub fn is_firefox_domain(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
}


pub fn is_firefox_email_id(text: &str) -> bool {
    let (local, domain) = text.split_once('@').unwrap_or((text, ""));
    let leading_ok = text.chars().next().is_some_and(|first| first != '-' && first != '.');
    leading_ok
        && (1..=FIREFOX_LOCAL_MAX).contains(&local.len())
        && (1..=FIREFOX_DOMAIN_MAX).contains(&domain.len())
        && local.chars().all(is_firefox_local)
        && domain.chars().all(is_firefox_domain)
}


pub fn is_firefox_id(text: &str) -> bool {
    is_firefox_guid(text) || is_firefox_email_id(text)
}


pub fn is_url_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~' | '/' | ':' | '?' | '=' | '&' | '+' | ',')
}


pub fn is_host_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | ':')
}


/// `https://` only, ASCII allowlist (no userinfo, `%`, quote, backslash, whitespace), host starting with a letter or digit.
pub fn is_update_url(text: &str) -> bool {
    let rest = text.strip_prefix(HTTPS_PREFIX).unwrap_or("");
    let host = rest.split(['/', '?']).next().unwrap_or("");
    text.len() <= MAX_UPDATE_URL_BYTES
        && host.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && host.chars().all(is_host_character)
        && rest.chars().all(is_url_character)
}
