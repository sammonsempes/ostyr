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
    #[error("the rule file {path} does not compile")]
    Compile {
        path: PathBuf,
        #[source]
        source: yara_x::errors::CompileError,
    },
}
