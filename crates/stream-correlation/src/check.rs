use ipnet::IpNet;
use regex::Regex;
use serde_json::Value;
use sigma_sql::error::SigmaError;
use sigma_sql::modifier::{Matcher, Modifiers};
use sigma_sql::value::{parse_pieces, Piece};
use std::collections::BTreeSet;
use std::net::IpAddr;


/// One value test of a field: strings become case-insensitive regexes, `re` stays case-sensitive.
#[derive(Debug, Clone)]
pub enum Check {
    Text(Vec<Regex>),
    Cidr(IpNet),
    Exact(String),
    Absent,
    Exists(bool),
}


pub const DASH_VARIANTS: &[char] = &['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];


pub const CASE_INSENSITIVE: &str = "(?is)";


fn bad_value(rule: &str, field: &str, reason: String) -> SigmaError {
    SigmaError::BadValue {
        rule: rule.to_string(),
        field: field.to_string(),
        reason,
    }
}


fn piece_regex(piece: &Piece) -> String {
    match piece {
        Piece::Literal(character) => regex::escape(&character.to_string()),
        Piece::Many => ".*".to_string(),
        Piece::One => ".".to_string(),
    }
}


pub fn string_pattern(matcher: Matcher, text: &str) -> String {
    let body: String = parse_pieces(text).iter().map(piece_regex).collect();
    match matcher {
        Matcher::Equals => format!("^{body}$"),
        Matcher::StartsWith => format!("^{body}"),
        Matcher::EndsWith => format!("{body}$"),
        _ => body,
    }
}


pub fn dash_variants(text: &str) -> Vec<String> {
    let variants: BTreeSet<String> = DASH_VARIANTS.iter().map(|dash| text.replace('-', &dash.to_string())).collect();
    variants.into_iter().collect()
}


fn string_regex(rule: &str, field: &str, matcher: Matcher, text: &str) -> Result<Regex, SigmaError> {
    Regex::new(&format!("{CASE_INSENSITIVE}{}", string_pattern(matcher, text))).map_err(|error| bad_value(rule, field, error.to_string()))
}


fn text_check(rule: &str, field: &str, modifiers: Modifiers, text: &str) -> Result<Check, SigmaError> {
    match modifiers.matcher {
        Matcher::Regex => Regex::new(text)
            .map(|pattern| Check::Text(vec![pattern]))
            .map_err(|error| bad_value(rule, field, error.to_string())),
        Matcher::Cidr => text
            .parse::<IpNet>()
            .map(Check::Cidr)
            .map_err(|error| bad_value(rule, field, error.to_string())),
        Matcher::Exists => Err(bad_value(rule, field, "exists takes true or false".to_string())),
        matcher => {
            let variants = if modifiers.windash {
                dash_variants(text)
            } else {
                vec![text.to_string()]
            };
            variants
                .iter()
                .map(|variant| string_regex(rule, field, matcher, variant))
                .collect::<Result<Vec<_>, _>>()
                .map(Check::Text)
        }
    }
}


/// Builds the check of one rule value, with the same value rules as the SQL compiler.
pub fn item_check(rule: &str, field: &str, modifiers: Modifiers, item: &Value) -> Result<Check, SigmaError> {
    match (modifiers.matcher, item) {
        (Matcher::Exists, Value::Bool(flag)) => Ok(Check::Exists(*flag)),
        (Matcher::Equals, Value::Null) => Ok(Check::Absent),
        (Matcher::Equals, Value::Bool(flag)) => Ok(Check::Exact(flag.to_string())),
        (Matcher::Equals, Value::Number(number)) => Ok(Check::Exact(number.to_string())),
        (_, Value::String(text)) => text_check(rule, field, modifiers, text),
        (_, Value::Number(number)) => text_check(rule, field, modifiers, &number.to_string()),
        _ => Err(bad_value(rule, field, "unsupported value type".to_string())),
    }
}


fn any_text(texts: Option<&Vec<String>>, test: impl Fn(&String) -> bool) -> bool {
    texts.is_some_and(|items| items.iter().any(test))
}


pub fn check_matches(check: &Check, texts: Option<&Vec<String>>) -> bool {
    match check {
        Check::Absent => texts.is_none(),
        Check::Exists(flag) => texts.is_some() == *flag,
        Check::Exact(expected) => any_text(texts, |text| text.eq_ignore_ascii_case(expected)),
        Check::Text(patterns) => any_text(texts, |text| patterns.iter().any(|pattern| pattern.is_match(text))),
        Check::Cidr(network) => any_text(texts, |text| text.parse::<IpAddr>().is_ok_and(|address| network.contains(&address))),
    }
}
