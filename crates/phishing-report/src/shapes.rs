use crate::model::Shapes;
use crate::urls::{split_region, Region};


const EDGE: usize = 2;


const OPENINGS: [&str; 2] = ["=\"", "='"];


const CID_MARKERS: [(&str, char); 2] = [("src=\"cid:", '"'), ("src='cid:", '\'')];


const ADDRESS_SEPARATOR: &str = " | ";


/// Which reasons an allowlisted shape removes; the host is listed whatever this says.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Vouched {
    pub ambiguity: bool,
    pub userinfo: bool,
}


fn is_gap(found: char) -> bool {
    matches!(found, ' ' | '\t' | '\n' | '\r' | '\x0c')
}


fn is_line_noise(found: char) -> bool {
    matches!(found, '\t' | '\n' | '\r')
}


fn is_name(found: char) -> bool {
    found.is_ascii_alphanumeric() || found == '-'
}


fn is_cid(found: char) -> bool {
    found.is_ascii_alphanumeric() || matches!(found, '.' | '_' | '-')
}


fn is_local(found: char) -> bool {
    found.is_ascii_alphanumeric() || matches!(found, '.' | '_' | '+' | '-')
}


fn is_domain(found: char) -> bool {
    found.is_ascii_alphanumeric() || matches!(found, '.' | '-')
}


/// Whether the part holds a character reference start: an `&` followed by `#` or an ASCII letter.
pub fn has_reference(html: &str) -> bool {
    html.split('&')
        .skip(1)
        .any(|segment| segment.starts_with(|first: char| first == '#' || first.is_ascii_alphabetic()))
}


/// The last `bound` bytes of `before`, cut on a character boundary.
pub fn window_before(before: &str, bound: usize) -> &str {
    let start = (before.len().saturating_sub(bound)..=before.len())
        .find(|index| before.is_char_boundary(*index))
        .unwrap_or(before.len());
    before.split_at_checked(start).map_or(before, |(_, rest)| rest)
}


/// The first `bound` bytes of `tail`, cut on a character boundary.
pub fn window_after(tail: &str, bound: usize) -> &str {
    let end = (0..=bound.min(tail.len())).rev().find(|index| tail.is_char_boundary(*index)).unwrap_or(0);
    tail.split_at_checked(end).map_or(tail, |(kept, _)| kept)
}


/// The last characters before a match, read from at most `bound` raw bytes, with TAB, CR and LF removed when `strip` is set.
pub fn edge(before: &str, bound: usize, strip: bool) -> String {
    let mut kept: Vec<char> = window_before(before, bound)
        .chars()
        .rev()
        .filter(|found| !(strip && is_line_noise(*found)))
        .take(EDGE)
        .collect();
    kept.reverse();
    kept.into_iter().collect()
}


/// At most `bound` raw bytes of `tail`, with TAB, CR and LF removed when `strip` is set.
pub fn head(tail: &str, bound: usize, strip: bool) -> String {
    window_after(tail, bound)
        .chars()
        .filter(|found| !(strip && is_line_noise(*found)))
        .collect()
}


fn attribute_follows(rest: &str) -> bool {
    let trimmed = rest.trim_start_matches(is_gap);
    trimmed.len() < rest.len()
        && trimmed
            .strip_prefix(|first: char| first.is_ascii_alphabetic())
            .is_some_and(|name| name.trim_start_matches(is_name).starts_with('='))
}


/// The match is a whole attribute value: `="` before, the same quote after, then `>` or another attribute.
pub fn closes_attribute(before: &str, head: &str) -> bool {
    OPENINGS
        .iter()
        .find(|opening| before.ends_with(**opening))
        .and_then(|opening| opening.chars().last())
        .and_then(|quote| head.strip_prefix(quote))
        .is_some_and(|rest| rest.starts_with('>') || attribute_follows(rest))
}


fn cid_ends(after: &str, quote: char) -> bool {
    let local = after.trim_start_matches(is_cid);
    local.len() < after.len()
        && local.strip_prefix('@').is_some_and(|domain| {
            let rest = domain.trim_start_matches(is_cid);
            rest.len() < domain.len() && rest.starts_with(quote)
        })
}


/// An Outlook `src="cid:name@host"` reference, the only `@` of the region, closed by its own quote inside it.
pub fn cid_reference(region: &str) -> bool {
    region.matches('@').count() == 1
        && CID_MARKERS
            .iter()
            .any(|(marker, quote)| region.split_once(marker).is_some_and(|(_, after)| cid_ends(after, *quote)))
}


/// ` | ` and one email address, the only `@`, ended by whitespace, a line end or the end of the text.
pub fn address_follows(region: &str, next: Option<char>) -> bool {
    region.strip_prefix(ADDRESS_SEPARATOR).is_some_and(|after| {
        let local = after.trim_start_matches(is_local);
        local.len() < after.len()
            && local.strip_prefix('@').is_some_and(|domain| {
                let rest = domain.trim_start_matches(is_domain);
                rest.len() < domain.len()
                    && !rest.contains('@')
                    && rest.chars().next().map_or(next.is_none_or(|end| end == '\n'), char::is_whitespace)
            })
    })
}


/// The shapes that hold on one reading of the text around a match.
pub fn vouch(shapes: Shapes, before: &str, head: &str, bound: usize) -> Vouched {
    let closed = closes_attribute(before, head);
    let (cid, address) = match split_region(head, bound) {
        Region::Closed(region) => (
            cid_reference(region),
            shapes == Shapes::Plain
                && !before.ends_with(['"', '\'', '='])
                && address_follows(region, head.get(region.len()..).and_then(|after| after.chars().next())),
        ),
        Region::Open => (false, false),
    };
    Vouched {
        ambiguity: closed,
        userinfo: closed || cid || address,
    }
}
