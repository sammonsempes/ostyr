use crate::limits::Limits;
use crate::model::Counts;
use crate::text::has_hostile;
use regex::Regex;
use std::sync::LazyLock;
use url::Url;


pub const URL_PATTERN: &str = r#"(?i)(?:\b(?:https?|ftp)://|\bdata:)[^\s"'<>]+"#;


const TRAILING: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}'];


pub static URL_RULE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| Regex::new(URL_PATTERN));


/// Turns the entities an HTML attribute may carry back into the characters of the URL.
pub fn html_text(html: &str) -> String {
    html.replace("&amp;", "&")
}


fn normalise(candidate: &str, limits: &Limits) -> Option<String> {
    let acceptable = candidate.len() <= limits.url_bytes && !has_hostile(candidate);
    if acceptable {
        match Url::parse(candidate) {
            Ok(parsed) => Some(String::from(parsed)),
            Err(_) => None,
        }
    } else {
        None
    }
}


fn add(mut urls: Vec<String>, candidate: &str, limits: &Limits, counts: &mut Counts) -> Vec<String> {
    let normalised = normalise(candidate.trim_end_matches(TRAILING), limits);
    counts.urls_refused += usize::from(normalised.is_none());
    let fresh = normalised.filter(|url| !urls.contains(url));
    counts.urls_dropped += usize::from(fresh.is_some() && urls.len() >= limits.urls);
    urls.extend(fresh.filter(|_| urls.len() < limits.urls));
    urls
}


/// Adds the URLs of `text` to `known`: deduplicated, at most `limits.urls`; a refused or dropped one is counted.
pub fn collect(rule: &Result<Regex, regex::Error>, text: &str, limits: &Limits, known: Vec<String>, counts: &mut Counts) -> Vec<String> {
    match rule {
        Ok(regex) => regex.find_iter(text).fold(known, |urls, found| add(urls, found.as_str(), limits, counts)),
        Err(error) => {
            tracing::error!(%error, "url pattern did not compile, no url is listed");
            counts.pattern_failed += 1;
            known
        }
    }
}
