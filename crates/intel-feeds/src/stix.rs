use crate::limits::{MAX_COMPARISONS_PER_PATTERN, MAX_PATTERN_BYTES};


pub const MARK: char = '\u{1}';


pub const MARK_TEXT: &str = "\u{1}";


pub const QUOTE: char = '\'';


pub const ESCAPE: char = '\\';


pub const PAIR: usize = 2;


pub const GROUP_SEPARATOR: &str = "] OR [";


pub const COMPARISON_SEPARATOR: &str = " OR ";


pub const EQUALS: &str = " = ";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternTerm {
    pub type_name: &'static str,
    pub value: String,
}


pub fn type_name_of_path(path: &str) -> Option<&'static str> {
    match path {
        "ipv4-addr:value" | "ipv6-addr:value" => Some("ip"),
        "domain-name:value" => Some("domain"),
        "url:value" => Some("url"),
        "file:hashes.MD5" => Some("md5"),
        "file:hashes.SHA-1" => Some("sha1"),
        "file:hashes.SHA-256" => Some("sha256"),
        _ => None,
    }
}


/// `path = 'value'`; a quoted hash name (`file:hashes.'SHA-256'`) takes one more literal before the value.
pub fn term_of<'literal>(comparison: &str, literals: &mut impl Iterator<Item = &'literal str>) -> Option<PatternTerm> {
    let (path, right) = comparison.split_once(EQUALS)?;
    let taken: Vec<&str> = literals.by_ref().take(comparison.matches(MARK).count()).collect();
    let (full_path, value) = match (path.strip_suffix(MARK), taken.as_slice()) {
        (Some(prefix), [algorithm, value]) => Some((format!("{prefix}{algorithm}"), *value)),
        (None, [value]) => Some((path.to_owned(), *value)),
        _ => None,
    }?;
    let type_name = type_name_of_path(&full_path).filter(|_| right == MARK_TEXT)?;
    Some(PatternTerm {
        type_name,
        value: value.to_owned(),
    })
}


/// Strings are cut out first, so every comparison is checked structurally; no recursion, no guessing.
pub fn comparisons_of(skeleton: &str, literals: Vec<&str>) -> Option<Vec<PatternTerm>> {
    let spaced = skeleton.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalised = spaced.replace("[ ", "[").replace(" ]", "]");
    let inner = normalised.strip_prefix('[')?.strip_suffix(']')?;
    let comparisons: Vec<&str> = inner.split(GROUP_SEPARATOR).flat_map(|group| group.split(COMPARISON_SEPARATOR)).collect();
    let mut remaining = literals.into_iter();
    let terms = comparisons
        .iter()
        .map(|comparison| term_of(comparison, &mut remaining))
        .collect::<Option<Vec<PatternTerm>>>()?;
    (comparisons.len() <= MAX_COMPARISONS_PER_PATTERN).then_some(terms)
}


/// Supports `[path = 'value']` comparisons joined by `OR`, inside or between brackets; `None` for everything else.
pub fn parse_pattern(pattern: &str) -> Option<Vec<PatternTerm>> {
    let segments: Vec<&str> = pattern.split(QUOTE).collect();
    let plain = !pattern.contains(ESCAPE) && !pattern.contains(MARK) && pattern.len() <= MAX_PATTERN_BYTES;
    if plain && segments.len() % PAIR == 1 {
        let skeleton = segments.iter().step_by(PAIR).copied().collect::<Vec<_>>().join(MARK_TEXT);
        let literals = segments.iter().skip(1).step_by(PAIR).copied().collect();
        comparisons_of(&skeleton, literals)
    } else {
        None
    }
}
