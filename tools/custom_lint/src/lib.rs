//! Workspace linter for the project coding rules that Clippy cannot check.


pub mod comments;
pub mod error;
pub mod model;
pub mod position;
pub mod rules;
pub mod rules_comments;
pub mod rules_flow;
pub mod rules_loops;
pub mod rules_names;
pub mod rules_recursion;
pub mod rules_spacing;
pub mod rules_types;
pub mod run;
pub mod scan;
pub mod tokens;
pub mod types;
