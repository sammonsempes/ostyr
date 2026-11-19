use crate::limits::Limits;
use crate::model::{Counts, UrlHit};
use crate::text::{has_hostile, is_zero_width};
use regex::Regex;
use std::sync::LazyLock;
use url::Url;


pub const URL_PATTERN: &str = r#"(?i)(?:\b(?:https?|ftp)://|\bdata:)[^\s"'<>]+"#;


const TRAILING: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}'];


const MAX_REFERENCE_CHARS: usize = 32;


pub static URL_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(URL_PATTERN));


fn is_reference(segment: &str) -> bool {
    segment.split_once(';').is_some_and(|(name, _)| {
        !name.is_empty() && name.len() <= MAX_REFERENCE_CHARS && name.chars().all(|candidate| candidate.is_ascii_alphanumeric() || candidate == '#')
    })
}


/// Decodes every HTML character reference (decimal, hex, named); a reference left as written is counted.
pub fn html_text(html: &str, counts: &mut Counts) -> String {
    let decoded = html_escape::decode_html_entities(html).into_owned();
    counts.html_refs_undecoded += decoded.split('&').skip(1).filter(|segment| is_reference(segment)).count();
    decoded
}


fn normalise(candidate: &str, limits: &Limits, counts: &mut Counts) -> Option<String> {
    let stripped: String = candidate
        .chars()
        .filter(|found| !is_zero_width(*found))
        .take(limits.url_bytes.saturating_add(1))
        .collect();
    let cleaned = candidate.chars().any(is_zero_width);
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
