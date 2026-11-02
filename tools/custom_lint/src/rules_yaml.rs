use crate::model::Violation;
use granit_parser::{Event, Parser};
use std::path::Path;


pub const YAML_COMMENT: &str = "yaml-comment";


pub fn yaml_comments(path: &Path, text: &str) -> Vec<Violation> {
    let mut failed = false;
    let found: Vec<Violation> = Parser::new_from_str(text)
        .map_while(|next| {
            failed = next.is_err();
            next.ok()
        })
        .filter(|(event, _)| matches!(event, Event::Comment(..)))
        .map(|(_, span)| Violation {
            path: path.to_path_buf(),
            line: span.start.line(),
            column: span.start.col() + 1,
            rule: YAML_COMMENT,
            message: "comments are not allowed in YAML files".to_string(),
        })
        .collect();
    if failed {
        tracing::warn!(path = %path.display(), "YAML file could not be scanned to the end");
    }
    found
}
