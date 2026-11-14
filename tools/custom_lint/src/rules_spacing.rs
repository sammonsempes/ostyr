use crate::model::{violation_at, Context, Violation};
use syn::{spanned::Spanned, Item};


pub const ITEM_SPACING: &str = "item-spacing";


const REQUIRED_BLANK_LINES: usize = 2;


pub fn group_name(item: &Item) -> Option<&'static str> {
    match item {
        Item::Use(_) => Some("use"),
        Item::Mod(module) if module.content.is_none() => Some("mod"),
        _ => None,
    }
}


pub fn blank_prefix_counts(source: &str) -> Vec<usize> {
    source
        .lines()
        .scan(0, |blank_total, line| {
            *blank_total += usize::from(line.trim().is_empty());
            Some(*blank_total)
        })
        .fold(vec![0], |mut counts, total| {
            counts.push(total);
            counts
        })
}


pub fn blank_lines_between(prefix: &[usize], previous_end: usize, next_start: usize) -> usize {
    let total = prefix.last().copied().unwrap_or(0);
    let count_before = |line_count: usize| prefix.get(line_count).copied().unwrap_or(total);
    count_before(next_start.max(previous_end + 1) - 1) - count_before(previous_end)
}


pub fn spacing_violation(context: &Context, prefix: &[usize], previous: &Item, next: &Item) -> Option<Violation> {
    let next_start = next.span().start();
    let blank_lines = blank_lines_between(prefix, previous.span().end().line, next_start.line);
    let group = group_name(previous).filter(|name| group_name(next) == Some(*name));
    let (required, message) = match group {
        Some(name) => (0, format!("expected no blank line inside a {name} group")),
        None => (
            REQUIRED_BLANK_LINES,
            format!("expected {REQUIRED_BLANK_LINES} blank lines between items, found {blank_lines}"),
        ),
    };
    (blank_lines != required).then(|| violation_at(context, ITEM_SPACING, (next_start.line, next_start.column + 1), message))
}


pub fn item_spacing(context: &Context) -> Vec<Violation> {
    let prefix = blank_prefix_counts(&context.source);
    context
        .file
        .items
        .iter()
        .zip(context.file.items.iter().skip(1))
        .filter_map(|(previous, next)| spacing_violation(context, &prefix, previous, next))
        .collect()
}
