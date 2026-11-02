use syn::{spanned::Spanned, Item};


use crate::model::{violation_at, Context, Violation};


pub const ITEM_SPACING: &str = "item-spacing";


const REQUIRED_BLANK_LINES: usize = 2;


pub fn spacing_violation(context: &Context, previous: &Item, next: &Item) -> Option<Violation> {
    let previous_end = previous.span().end().line;
    let next_start = next.span().start();
    let blank_lines = next_start.line.saturating_sub(previous_end + 1);
    (blank_lines != REQUIRED_BLANK_LINES).then(|| {
        violation_at(
            context,
            ITEM_SPACING,
            (next_start.line, next_start.column + 1),
            format!("expected {REQUIRED_BLANK_LINES} blank lines between items, found {blank_lines}"),
        )
    })
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
