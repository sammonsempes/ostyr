use crate::model::{AuthVerdicts, Counts};
use std::collections::BTreeSet;


pub const PASS: &str = "pass";


pub const UNKNOWN: &str = "unknown";


pub const CONFLICT: &str = "conflict";


pub const NO_TRUSTED_HEADER: &str = "no_trusted_header";


pub const OVERSIZED_HEADER: &str = "oversized_header";


const RESULTS: &[&str] = &[
    "pass",
    "fail",
    "softfail",
    "hardfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "policy",
    "declined",
    "unknown",
];


#[derive(Debug, Default)]
struct Split {
    fields: Vec<String>,
    current: String,
    depth: usize,
    quoted: bool,
    escaped: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub id: String,
    pub results: Vec<(String, String)>,
    pub pass_from: Vec<Vec<String>>,
}


fn step(mut state: Split, candidate: char) -> Split {
    let in_comment = state.depth > 0;
    match (state.escaped, in_comment, state.quoted, candidate) {
        (true, _, true, _) => {
            state.current.push(candidate);
            state.escaped = false;
        }
        (true, ..) => state.escaped = false,
        (false, true, _, '(') => state.depth += 1,
        (false, true, _, ')') => {
            state.depth = state.depth.saturating_sub(1);
            state.current.push_str(if state.depth == 0 { " " } else { "" });
        }
        (false, true, _, '\\') => state.escaped = true,
        (false, true, ..) => {}
        (false, false, true, '"') => {
            state.quoted = false;
            state.current.push(candidate);
        }
        (false, false, true, '\\') => {
            state.escaped = true;
            state.current.push(candidate);
        }
        (false, false, true, _) => state.current.push(candidate),
        (false, false, false, '"') => {
            state.quoted = true;
            state.current.push(candidate);
        }
        (false, false, false, '(') => state.depth = 1,
        (false, false, false, ';') => {
            let field = std::mem::take(&mut state.current);
            state.fields.push(field);
        }
        (false, false, false, _) => state.current.push(candidate),
    }
    state
}


/// Splits a header value at the semicolons outside quoted strings and comments (RFC 8601 section 2.2); None when a quote or comment is unbalanced.
pub fn split_fields(text: &str) -> Option<Vec<String>> {
    let end = text.chars().fold(Split::default(), step);
    let closed = !end.quoted && end.depth == 0 && !end.escaped;
    closed.then(|| {
        let mut fields = end.fields;
        fields.push(end.current);
        fields
    })
}


fn field_result(field: &str, counts: &mut Counts) -> Option<(String, String)> {
    let (method, rest) = field.split_once('=')?;
    let name = method.trim().split('/').next().map_or_else(String::new, str::to_ascii_lowercase);
    let result = rest.split_whitespace().next().map_or_else(String::new, str::to_ascii_lowercase);
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|candidate| candidate.is_ascii_alphanumeric() || matches!(candidate, '-' | '_' | '.'))
        && RESULTS.contains(&result.as_str());
    counts.auth_refused += usize::from(!valid);
    valid.then_some((name, result))
}


const HEADER_FROM: &str = "header.from=";


/// Splits at whitespace outside double quotes, so `header.from="a b"` stays one token.
fn quoted_tokens(field: &str) -> Vec<String> {
    let (mut tokens, current, _) = field
        .chars()
        .fold((Vec::new(), String::new(), false), |(mut tokens, mut current, quoted), candidate| {
            let quoted_now = quoted != (candidate == '"');
            if candidate.is_whitespace() && !quoted {
                tokens.push(std::mem::take(&mut current));
            } else {
                current.push(candidate);
            }
            (tokens, current, quoted_now)
        });
    tokens.push(current);
    tokens.into_iter().filter(|token| !token.is_empty()).collect()
}


/// The `header.from` values of one result field, lowered and unquoted; a quoted value holding a space stays whole and so never equals a domain.
fn header_from_values(field: &str) -> Vec<String> {
    quoted_tokens(field)
        .iter()
        .filter_map(|token| {
            let head = token.get(..HEADER_FROM.len()).filter(|head| head.eq_ignore_ascii_case(HEADER_FROM));
            head.and_then(|_| token.get(HEADER_FROM.len()..))
        })
        .map(|value| value.trim_matches('"').to_ascii_lowercase())
        .collect()
}


fn is_dmarc_pass(result: &(String, String)) -> bool {
    result.0 == "dmarc" && result.1 == PASS
}


/// The authserv-id and the method results of one header value; None (counted) when a quote or comment is unbalanced.
pub fn parse_header(text: &str, counts: &mut Counts) -> Option<Parsed> {
    let fields = split_fields(text);
    counts.auth_refused += usize::from(fields.is_none());
    fields.map(|all| {
        let read: Vec<(&String, (String, String))> = all
            .iter()
            .skip(1)
            .filter_map(|field| field_result(field, counts).map(|result| (field, result)))
            .collect();
        Parsed {
            id: all
                .first()
                .and_then(|first| first.split_whitespace().next())
                .map_or_else(String::new, str::to_ascii_lowercase),
            pass_from: read
                .iter()
                .filter(|(_, result)| is_dmarc_pass(result))
                .map(|(field, _)| header_from_values(field))
                .collect(),
            results: read.into_iter().map(|(_, result)| result).collect(),
        }
    })
}


fn is_trusted(id: &str, trusted: &[String]) -> bool {
    !id.is_empty() && trusted.iter().any(|candidate| candidate.eq_ignore_ascii_case(id))
}


fn method_verdict(headers: &[Parsed], method: &str) -> String {
    let found: BTreeSet<&str> = headers
        .iter()
        .flat_map(|header| header.results.iter())
        .filter(|(name, _)| name == method)
        .map(|(_, result)| result.as_str())
        .collect();
    match found.iter().collect::<Vec<_>>().as_slice() {
        [] => UNKNOWN.to_owned(),
        [only] => (**only).to_owned(),
        _ => CONFLICT.to_owned(),
    }
}


/// The verdicts of the headers whose authserv-id is trusted; none trusted gives `unknown` with a reason, two results for a method give `conflict`.
pub fn verdicts(texts: &[Option<&str>], trusted: &[String], oversized: bool, counts: &mut Counts) -> AuthVerdicts {
    verdicts_with_from(texts, trusted, oversized, counts).0
}


/// The verdicts plus, for each trusted `dmarc=pass` result, its `header.from` values (empty when the property is missing).
pub fn verdicts_with_from(texts: &[Option<&str>], trusted: &[String], oversized: bool, counts: &mut Counts) -> (AuthVerdicts, Vec<Vec<String>>) {
    if oversized {
        let verdict = AuthVerdicts {
            reason: Some(OVERSIZED_HEADER.to_owned()),
            ..AuthVerdicts::default()
        };
        (verdict, Vec::new())
    } else {
        counts.auth_refused += texts.iter().filter(|text| text.is_none()).count();
        let parsed: Vec<Parsed> = texts.iter().flatten().filter_map(|text| parse_header(text, counts)).collect();
        let (own, foreign): (Vec<Parsed>, Vec<Parsed>) = parsed.into_iter().partition(|header| is_trusted(&header.id, trusted));
        counts.auth_untrusted += foreign.len();
        let verdict = AuthVerdicts {
            spf: method_verdict(&own, "spf"),
            dkim: method_verdict(&own, "dkim"),
            dmarc: method_verdict(&own, "dmarc"),
            reason: own.is_empty().then(|| NO_TRUSTED_HEADER.to_owned()),
        };
        (verdict, own.into_iter().flat_map(|header| header.pass_from).collect())
    }
}
