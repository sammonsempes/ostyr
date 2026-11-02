use crate::{
    model::Rule,
    rules_comments::{doc_comment_multiline, line_comment, DOC_COMMENT_MULTILINE, LINE_COMMENT},
    rules_spacing::{item_spacing, ITEM_SPACING},
};


pub const RULES: &[Rule] = &[
    Rule {
        id: LINE_COMMENT,
        check: line_comment,
    },
    Rule {
        id: DOC_COMMENT_MULTILINE,
        check: doc_comment_multiline,
    },
    Rule {
        id: ITEM_SPACING,
        check: item_spacing,
    },
];
