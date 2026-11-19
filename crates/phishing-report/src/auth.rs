use crate::model::{AuthVerdicts, Counts};


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


/// Removes every parenthesised comment: a comment may carry text the sender chose, so a semicolon in it must not open a field.
pub fn strip_comments(text: &str) -> String {
    text.chars()
        .fold((usize::default(), String::new()), |(depth, mut kept), candidate| match candidate {
            '(' => (depth.saturating_add(1), kept),
            ')' => (depth.saturating_sub(1), kept),
            _ if depth == 0 => {
                kept.push(candidate);
                (depth, kept)
            }
            _ => (depth, kept),
        })
        .1
}


fn record(verdicts: AuthVerdicts, field: &str, counts: &mut Counts) -> AuthVerdicts {
    let (method, result) = field
        .split_whitespace()
        .next()
        .and_then(|token| token.split_once('='))
        .map_or((String::new(), String::new()), |(method, result)| {
            (method.to_ascii_lowercase(), result.to_ascii_lowercase())
        });
    let known = RESULTS.contains(&result.as_str());
    counts.auth_refused += usize::from(!result.is_empty() && !known);
    let kept = known.then_some(result);
    match method.as_str() {
        "spf" => AuthVerdicts {
            spf: verdicts.spf.or(kept),
            ..verdicts
        },
        "dkim" => AuthVerdicts {
            dkim: verdicts.dkim.or(kept),
            ..verdicts
        },
        "dmarc" => AuthVerdicts {
            dmarc: verdicts.dmarc.or(kept),
            ..verdicts
        },
        _ => verdicts,
    }
}


/// Reads spf, dkim and dmarc results from one `Authentication-Results` value; the first result per method wins, an unknown result is refused.
pub fn verdicts(header_value: &str, counts: &mut Counts) -> AuthVerdicts {
    strip_comments(header_value)
        .split(';')
        .skip(1)
        .fold(AuthVerdicts::default(), |found, field| record(found, field, counts))
}


/// The authserv-id: the first token before the first semicolon, lower-cased.
pub fn authserv_id(header_value: &str) -> String {
    strip_comments(header_value)
        .split(';')
        .next()
        .and_then(|id| id.split_whitespace().next())
        .map_or_else(String::new, str::to_ascii_lowercase)
}


/// Keeps what `found` has and fills the gaps from `later`: the header nearest the top wins.
pub fn merge(found: AuthVerdicts, later: AuthVerdicts) -> AuthVerdicts {
    AuthVerdicts {
        spf: found.spf.or(later.spf),
        dkim: found.dkim.or(later.dkim),
        dmarc: found.dmarc.or(later.dmarc),
    }
}
