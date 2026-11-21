use crate::model::ReporterPolicy;
use crate::policy::MAX_DOMAIN_BYTES;
use std::collections::HashSet;


const WHITESPACE: &[u8] = b" \t\r\n";


const STEPS_PER_BYTE: usize = 4;


const STEPS_FLOOR: usize = 1024;


const MAX_RUN: usize = MAX_DOMAIN_BYTES + 1;


/// What the byte scan of one raw `From` value found: a claim, a spent step budget (also a claim, counted) and the lookups made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimScan {
    pub claimed: bool,
    pub exhausted: bool,
    pub lookups: usize,
}


#[derive(Debug, Default)]
struct Walk {
    depth: usize,
    escaped: bool,
    bracketed: bool,
    run: usize,
}


#[derive(Debug)]
struct Look {
    domain: String,
    used: usize,
    exhausted: bool,
}


#[derive(Debug, Clone, Copy)]
struct Totals {
    budget: usize,
    lookups: usize,
}


/// The policy domains lowered once per triage: one hash lookup per at sign, never a walk of the list.
pub fn domain_set(policy: &ReporterPolicy) -> HashSet<String> {
    policy.internal_domains.iter().map(|domain| domain.to_ascii_lowercase()).collect()
}


fn in_comment(walk: &mut Walk, byte: u8) -> Option<Option<u8>> {
    let escaped = walk.escaped;
    walk.escaped = !escaped && byte == b'\\';
    walk.depth = match (escaped, byte) {
        (false, b'(') => walk.depth + 1,
        (false, b')') => walk.depth.saturating_sub(1),
        _ => walk.depth,
    };
    Some(None)
}


/// One byte after an at sign: `Some(None)` is skipped (comment, bracket), `Some(Some(byte))` a domain byte, `None` ends the walk.
fn step(walk: &mut Walk, byte: u8) -> Option<Option<u8>> {
    let before_run = walk.run == 0 && !walk.bracketed;
    if walk.depth > 0 {
        in_comment(walk, byte)
    } else if before_run && WHITESPACE.contains(&byte) {
        Some(None)
    } else if before_run && byte == b'(' {
        walk.depth = 1;
        Some(None)
    } else if before_run && byte == b'[' {
        walk.bracketed = true;
        Some(None)
    } else if (byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.') && walk.run < MAX_RUN {
        walk.run += 1;
        Some(Some(byte))
    } else {
        None
    }
}


/// The text after one at sign: whitespace, comments and one `[` skipped before the first domain byte, then the maximal run of letters, digits, dots and hyphens.
fn look(rest: &[u8], budget: usize) -> Look {
    let items: Vec<Option<u8>> = rest.iter().take(budget).scan(Walk::default(), |walk, byte| step(walk, *byte)).collect();
    Look {
        domain: items.iter().flatten().map(|byte| char::from(*byte)).collect(),
        used: items.len() + 1,
        exhausted: items.len() == budget && items.len() < rest.len(),
    }
}


fn visit(totals: Totals, rest: &[u8], domains: &HashSet<String>) -> Result<Totals, ClaimScan> {
    let found = look(rest, totals.budget);
    let lookups = totals.lookups + 1;
    let lowered = found.domain.strip_suffix('.').unwrap_or(&found.domain).to_ascii_lowercase();
    if found.exhausted || domains.contains(&lowered) {
        Err(ClaimScan {
            claimed: true,
            exhausted: found.exhausted,
            lookups,
        })
    } else {
        Ok(Totals {
            budget: totals.budget.saturating_sub(found.used),
            lookups,
        })
    }
}


fn read_ats(bytes: &[u8], start: Totals, domains: &HashSet<String>) -> Result<Totals, ClaimScan> {
    bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'@')
        .filter_map(|(index, _)| bytes.get(index + 1..))
        .try_fold(start, |totals, rest| visit(totals, rest, domains))
}


/// Every at sign of a raw `From` value, whatever it sits in, is read as the start of a domain twice: as written, then with all whitespace removed.
pub fn claim_scan(raw: &[u8], domains: &HashSet<String>) -> ClaimScan {
    let start = Totals {
        budget: raw.len().saturating_mul(STEPS_PER_BYTE).saturating_add(STEPS_FLOOR),
        lookups: 0,
    };
    let squeezed: Vec<u8> = raw.iter().copied().filter(|byte| !WHITESPACE.contains(byte)).collect();
    match read_ats(raw, start, domains).and_then(|totals| read_ats(&squeezed, totals, domains)) {
        Ok(totals) => ClaimScan {
            claimed: false,
            exhausted: false,
            lookups: totals.lookups,
        },
        Err(found) => found,
    }
}
