use crate::audit::open_audit;
use crate::error::CliError;
use crate::open::{decide_open, Evidence, OpenRequest};
use crate::policy::load_policy;
use crate::types::Seconds;
use cmdb::model::Criticality;
use core_auth::types::{RoleCatalog, RoleSet};
use core_config::error::ConfigError;
use core_config::parse::read_text_capped;
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;


pub const MAX_CASE_BYTES: u64 = 65_536;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCase {
    pub catalog: RoleCatalog,
    pub request: OpenRequest,
    pub requester_roles: RoleSet,
    pub asset_criticality: Option<Criticality>,
    pub evidence: Evidence,
    pub now: Seconds,
}


pub fn load_case(path: &Path) -> Result<ShellCase, CliError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    let text = read_text_capped(&mut handle, &file, MAX_CASE_BYTES)?;
    serde_json::from_str(&text).map_err(|source| CliError::Case { file, source })
}


/// `args` are the policy file and the case file; prints the decision and the audit fields.
pub fn run_cli(args: &[String], out: &mut dyn Write) -> Result<(), CliError> {
    match args {
        [policy_path, case_path] => {
            let policy = load_policy(Path::new(policy_path))?;
            let case = load_case(Path::new(case_path))?;
            let decision = decide_open(
                &policy,
                &case.catalog,
                &case.request,
                &case.requester_roles,
                case.asset_criticality,
                &case.evidence,
                case.now,
            );
            let fields = open_audit(&case.request, &decision);
            writeln!(out, "{decision:?}\n{fields:?}")?;
            Ok(())
        }
        _ => Err(CliError::Usage),
    }
}
