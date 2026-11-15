use std::io;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum NdrError {
    #[error("cannot list the rules directory {path}")]
    RulesDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read the rule file {path}")]
    RuleRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the rule file {path} is larger than {max_bytes} bytes")]
    RuleTooLarge { path: PathBuf, max_bytes: u64 },
    #[error("the rules directory holds more than {max_files} rule files")]
    TooManyRuleFiles { max_files: usize },
    #[error("the rules directory holds no rule file")]
    NoRules,
    #[error("the yr program {path} is refused: {reason}")]
    Program { path: PathBuf, reason: &'static str },
    #[error("cannot prepare the private work directory")]
    Workspace(#[source] io::Error),
    #[error("cannot start yr")]
    Spawn(#[source] io::Error),
    #[error("cannot read the output of yr")]
    Output(#[source] io::Error),
    #[error("yr did not compile the rules (exit ok: {exited_ok}, timed out: {timed_out}, output cut: {cut}): {stderr}")]
    Compile {
        exited_ok: bool,
        timed_out: bool,
        cut: bool,
        stderr: String,
    },
}
