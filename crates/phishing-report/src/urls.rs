use crate::limits::Limits;
use crate::model::{Counts, UrlHit, UrlIndex};
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
    text.push_str(stripped.as_deref().unwrap_or(""));
    text.push_str(&attributes);
    text.push('\n');
    text.push_str(&decoded);
    text
}


/// `html_text_with` and the built-in attribute rule.
pub fn html_text(html: &str, counts: &mut Counts) -> String {
    html_text_with(&ATTRIBUTE_RULE, html, counts)
}


fn strip_noise(candidate: &str, limits: &Limits) -> String {
    candidate
        .chars()
        .filter(|found| !is_url_noise(*found))
        .take(limits.url_bytes.saturating_add(1))
        .collect()
}


fn normalise(candidate: &str, limits: &Limits, counts: &mut Counts) -> Option<String> {
    let stripped = strip_noise(candidate, limits);
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


const AUTHORITY_END: &[char] = &['/', '?', '#', '\\'];


const DATA_SCHEME: &str = "data:";


fn authority_ends(stripped: &str) -> bool {
    stripped
        .split_once(':')
        .is_some_and(|(_, rest)| rest.trim_start_matches(['/', '\\']).contains(AUTHORITY_END))
}


fn is_data(stripped: &str) -> bool {
    stripped
        .chars()
        .take(DATA_SCHEME.len())
        .collect::<String>()
        .eq_ignore_ascii_case(DATA_SCHEME)
}


fn refused_host(stripped: &str, too_long: bool) -> Option<String> {
    Some(stripped)
        .filter(|text| too_long || has_hostile(text))
        .filter(|text| !too_long || authority_ends(text))
        .and_then(|text| Url::parse(text).ok())
        .and_then(|parsed| parsed.domain().map(str::to_owned))
}


/// The kept URLs and refused hosts as sets, so a candidate costs one hash of its own length whatever the number kept.
pub fn index_from(urls: &[UrlHit], hosts: Vec<String>) -> UrlIndex {
    UrlIndex {
        seen: urls.iter().map(|hit| hit.url.clone()).collect(),
        hosts_seen: hosts.iter().cloned().collect(),
        hosts,
        probes: 0,
        probed_bytes: 0,
    }
}


fn is_new(index: &mut UrlIndex, url: &str) -> bool {
    index.probes += 1;
    index.probed_bytes += url.len();
    !index.seen.contains(url)
}


fn keep_host(index: &mut UrlIndex, host: String, limits: &Limits, counts: &mut Counts) {
    let fresh = !index.hosts_seen.contains(&host);
    let room = index.hosts.len() < limits.urls;
    counts.urls_dropped += usize::from(fresh && !room);
    counts.url_cap_reached = counts.url_cap_reached.max(usize::from(fresh && !room));
    counts.url_refused_host_kept += usize::from(fresh && room);
    if fresh && room {
        index.hosts_seen.insert(host.clone());
        index.hosts.push(host);
    }
}


fn refuse(trimmed: &str, limits: &Limits, index: &mut UrlIndex, counts: &mut Counts) {
    let stripped = strip_noise(trimmed, limits);
    let too_long = stripped.len() > limits.url_bytes;
    let host = refused_host(&stripped, too_long);
    counts.url_host_unread += usize::from(too_long && host.is_none() && !is_data(&stripped));
    if let Some(found) = host {
        keep_host(index, found, limits, counts);
    }
}


fn add(mut urls: Vec<UrlHit>, candidate: &str, level: usize, limits: &Limits, index: &mut UrlIndex, counts: &mut Counts) -> Vec<UrlHit> {
    let trimmed = candidate.trim_end_matches(TRAILING);
    let normalised = normalise(trimmed, limits, counts);
    counts.urls_refused += usize::from(normalised.is_none());
    if normalised.is_none() {
        refuse(trimmed, limits, index, counts);
    }
    let fresh = normalised.filter(|url| is_new(index, url));
    let full = urls.len() >= limits.urls;
    counts.urls_dropped += usize::from(fresh.is_some() && full);
    counts.url_cap_reached = counts.url_cap_reached.max(usize::from(fresh.is_some() && full));
    if let Some(url) = fresh.filter(|_| !full) {
        index.seen.insert(url.clone());
        urls.push(UrlHit { level, url });
    }
    urls
}


/// Adds the URLs of `text` to `known`: deduplicated through `index`, at most `limits.urls`; a refused or dropped one is counted.
pub fn collect_indexed(
    rule: &Result<Regex, regex::Error>,
    text: &str,
    level: usize,
    limits: &Limits,
    known: Vec<UrlHit>,
    index: &mut UrlIndex,
    counts: &mut Counts,
) -> Vec<UrlHit> {
    match rule {
        Ok(regex) => regex
            .find_iter(text)
            .fold(known, |urls, found| add(urls, found.as_str(), level, limits, index, counts)),
        Err(error) => {
            tracing::error!(%error, "url pattern did not compile, no url is listed");
            counts.pattern_failed += 1;
            known
        }
    }
}


/// `collect_indexed` with an index built from `known` and dropped afterwards.
pub fn collect(
    rule: &Result<Regex, regex::Error>,
    text: &str,
    level: usize,
    limits: &Limits,
    known: Vec<UrlHit>,
    counts: &mut Counts,
) -> Vec<UrlHit> {
    let mut index = index_from(&known, Vec::new());
    collect_indexed(rule, text, level, limits, known, &mut index, counts)
}
