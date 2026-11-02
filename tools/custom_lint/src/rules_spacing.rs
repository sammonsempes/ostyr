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


pub fn blank_lines_between(source: &str, previous_end: usize, next_start: usize) -> usize {
    source
        .lines()
        .skip(previous_end)
        .take(next_start.saturating_sub(previous_end + 1))
        .filter(|line| line.trim().is_empty())
        .count()
}


pub fn spacing_violation(context: &Context, previous: &Item, next: &Item) -> Option<Violation> {
    let next_start = next.span().start();
    let blank_lines = blank_lines_between(&context.source, previous.span().end().line, next_start.line);
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
    context
        .file
        .items
        .iter()
        .zip(context.file.items.iter().skip(1))
        .filter_map(|(previous, next)| spacing_violation(context, previous, next))
        .collect()
}
