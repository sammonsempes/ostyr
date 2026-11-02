use crate::{
    model::Rule,
    rules_comments::{doc_comment_multiline, line_comment, DOC_COMMENT_MULTILINE, LINE_COMMENT},
    rules_flow::{bare_loop, break_continue, process_exit, return_expression, BARE_LOOP, BREAK_CONTINUE, PROCESS_EXIT, RETURN},
    rules_loops::{loop_nesting, uncapped_while, LOOP_NESTING, UNCAPPED_WHILE},
    rules_names::{forbidden_ident, global_mutable, magic_number, FORBIDDEN_IDENT, GLOBAL_MUTABLE, MAGIC_NUMBER},
    rules_recursion::{recursion, RECURSION},
    rules_spacing::{item_spacing, ITEM_SPACING},
    rules_types::{
        any_type, custom_trait, impl_allowlist, inherent_impl, type_alias_location, ANY_TYPE, CUSTOM_TRAIT, IMPL_ALLOWLIST, INHERENT_IMPL,
        TYPE_ALIAS_LOCATION,
    },
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
    Rule {
        id: INHERENT_IMPL,
        check: inherent_impl,
    },
    Rule {
        id: CUSTOM_TRAIT,
        check: custom_trait,
    },
    Rule {
        id: IMPL_ALLOWLIST,
        check: impl_allowlist,
    },
    Rule {
        id: ANY_TYPE,
        check: any_type,
    },
    Rule {
        id: TYPE_ALIAS_LOCATION,
        check: type_alias_location,
    },
    Rule {
        id: FORBIDDEN_IDENT,
        check: forbidden_ident,
    },
    Rule {
        id: MAGIC_NUMBER,
        check: magic_number,
    },
    Rule {
        id: GLOBAL_MUTABLE,
        check: global_mutable,
    },
];
