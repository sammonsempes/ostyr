use std::{fmt, path::PathBuf};


use crate::types::Position;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub rule: &'static str,
    pub message: String,
}


impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}: {}: {}",
            self.path.display(),
            self.line,
            self.column,
            self.rule,
            self.message
        )
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    Line,
    Block,
    DocLine,
    DocBlock,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    pub kind: CommentKind,
    pub offset: usize,
    pub text: String,
}


pub struct Context {
    pub path: PathBuf,
    pub source: String,
    pub comments: Vec<Comment>,
    pub file: syn::File,
}


#[derive(Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub check: fn(&Context) -> Vec<Violation>,
}


pub fn violation_at(context: &Context, rule: &'static str, position: Position, message: String) -> Violation {
    Violation {
        path: context.path.clone(),
        line: position.0,
        column: position.1,
        rule,
        message,
    }
}
