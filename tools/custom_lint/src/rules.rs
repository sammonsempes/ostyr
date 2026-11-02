use crate::{
    model::Rule,
    rules_comments::{doc_comment_multiline, line_comment, DOC_COMMENT_MULTILINE, LINE_COMMENT},
    rules_flow::{bare_loop, break_continue, process_exit, return_expression, BARE_LOOP, BREAK_CONTINUE, PROCESS_EXIT, RETURN},
    rules_loops::{loop_nesting, uncapped_while, LOOP_NESTING, UNCAPPED_WHILE},
    rules_recursion::{recursion, RECURSION},
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
    Rule {
        id: RETURN,
        check: return_expression,
    },
    Rule {
        id: BREAK_CONTINUE,
        check: break_continue,
    },
    Rule {
        id: BARE_LOOP,
        check: bare_loop,
    },
    Rule {
        id: UNCAPPED_WHILE,
        check: uncapped_while,
    },
    Rule {
        id: LOOP_NESTING,
        check: loop_nesting,
    },
    Rule {
        id: RECURSION,
        check: recursion,
    },
    Rule {
        id: PROCESS_EXIT,
        check: process_exit,
    },
];
