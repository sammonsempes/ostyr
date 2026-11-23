use crate::limits::Limits;
use crate::model::{Counts, UrlHit};
use crate::text::{has_hostile, is_zero_width};
use regex::Regex;
use std::sync::LazyLock;
use url::Url;


pub const URL_PATTERN: &str =
    r#"(?i)(?:\b(?:h[\t\n\r]*t[\t\n\r]*t[\t\n\r]*p[\t\n\r]*s?|f[\t\n\r]*t[\t\n\r]*p)[\t\n\r]*:[\t\n\r]*[/\\]*|\bdata[\t\n\r]*:)[^\s"'<>]+"#;


/// An attribute value as the HTML tokenizer cuts it: double quoted, single quoted or bare.
pub const ATTRIBUTE_PATTERN: &str = r#"=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>=`]+))"#;


const ATTRIBUTE_GROUPS: usize = 3;


const TRAILING: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}'];


pub static URL_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(URL_PATTERN));


pub static ATTRIBUTE_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(ATTRIBUTE_PATTERN));


fn is_reference(segment: &str) -> bool {
    segment
        .split_once(';')
        .is_some_and(|(name, _)| !name.is_empty() && name.chars().all(|candidate| candidate.is_ascii_alphanumeric() || candidate == '#'))
}


fn is_url_noise(found: char) -> bool {
    matches!(found, '\t' | '\n' | '\r') || is_zero_width(found)
}


fn changed_value(raw: &str) -> Option<String> {
    let decoded = htmlize::unescape_attribute(raw);
    let cleaned: String = decoded
        .trim_matches(|edge: char| edge <= ' ')
        .chars()
        .filter(|found| !matches!(found, '\t' | '\n' | '\r'))
        .collect();
    Some(cleaned).filter(|value| value.as_str() != decoded)
}


fn without_line_noise(decoded: &str) -> String {
    decoded.chars().filter(|found| !matches!(found, '\t' | '\n' | '\r')).collect()
}


fn attribute_values(rule: &Result<Regex, regex::Error>, html: &str, counts: &mut Counts) -> String {
    match rule {
        Ok(regex) => regex
            .captures_iter(html)
            .filter_map(|captured| (1..=ATTRIBUTE_GROUPS).find_map(|group| captured.get(group)))
            .filter_map(|value| changed_value(value.as_str()))
            .fold(String::new(), |mut joined, value| {
                joined.push('\n');
                joined.push_str(&value);
                joined
            }),
        Err(error) => {
            tracing::error!(%error, "attribute pattern did not compile, no attribute is re-read");
            counts.pattern_failed += 1;
            String::new()
        }
    }
}


/// Decodes an HTML part as a browser does in an attribute, appends the part without TAB, CR and LF and each attribute value read differently, counts every lost reference.
pub fn html_text_with(rule: &Result<Regex, regex::Error>, html: &str, counts: &mut Counts) -> String {
    let decoded = htmlize::unescape_attribute(html).into_owned();
    let replaced = decoded
        .matches(char::REPLACEMENT_CHARACTER)
        .count()
        .saturating_sub(html.matches(char::REPLACEMENT_CHARACTER).count());
    counts.html_refs_undecoded += replaced + decoded.split('&').skip(1).filter(|segment| is_reference(segment)).count();
    let attributes = attribute_values(rule, html, counts);
    let stripped = Some(without_line_noise(&decoded)).filter(|candidate| candidate.len() != decoded.len());
    let mut text = String::with_capacity(decoded.len() + stripped.as_ref().map_or(0, String::len) + attributes.len() + 1);
    text.push_str(&decoded);
    text.push('\n');
    text.push_str(stripped.as_deref().unwrap_or(""));
    text.push_str(&attributes);
    text
}


/// `html_text_with` and the built-in attribute rule.
pub fn html_text(html: &str, counts: &mut Counts) -> String {
    html_text_with(&ATTRIBUTE_RULE, html, counts)
}


fn normalise(candidate: &str, limits: &Limits, counts: &mut Counts) -> Option<String> {
    let stripped: String = candidate
        .chars()
        .filter(|found| !is_url_noise(*found))
        .take(limits.url_bytes.saturating_add(1))
        .collect();
    let cleaned = candidate.chars().any(is_url_noise);
    let acceptable = stripped.len() <= limits.url_bytes && !has_hostile(&stripped);
    if acceptable {
        counts.urls_cleaned += usize::from(cleaned);
        match Url::parse(&stripped) {
            Ok(parsed) => Some(String::from(parsed)),
            Err(_) => None,
        }
    } else {
        None
    }
}


fn add(mut urls: Vec<UrlHit>, candidate: &str, level: usize, limits: &Limits, counts: &mut Counts) -> Vec<UrlHit> {
    let normalised = normalise(candidate.trim_end_matches(TRAILING), limits, counts);
    counts.urls_refused += usize::from(normalised.is_none());
    let fresh = normalised.filter(|url| !urls.iter().any(|hit| &hit.url == url));
    counts.urls_dropped += usize::from(fresh.is_some() && urls.len() >= limits.urls);
    urls.extend(fresh.filter(|_| urls.len() < limits.urls).map(|url| UrlHit { level, url }));
    urls
}


/// Adds the URLs of `text` to `known`: deduplicated, at most `limits.urls`; a refused or dropped one is counted.
pub fn collect(
    rule: &Result<Regex, regex::Error>,
    text: &str,
    level: usize,
    limits: &Limits,
    known: Vec<UrlHit>,
    counts: &mut Counts,
) -> Vec<UrlHit> {
    match rule {
        Ok(regex) => regex
            .find_iter(text)
            .fold(known, |urls, found| add(urls, found.as_str(), level, limits, counts)),
        Err(error) => {
            tracing::error!(%error, "url pattern did not compile, no url is listed");
            counts.pattern_failed += 1;
            known
        }
    }
}
