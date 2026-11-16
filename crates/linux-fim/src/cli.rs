use crate::error::CliError;
use crate::model::Limits;
use crate::policy::render_policy;
use crate::roles::load_roles;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;


/// Reads the table at `table_path` under the size cap, renders the policy of `role_name` and writes it to `out`.
pub fn render_command<Output: Write>(table_path: &Path, role_name: &str, limits: &Limits, out: &mut Output) -> Result<(), CliError> {
    let mut text = String::new();
    let cap = (limits.max_table_bytes as u64).saturating_add(1);
    File::open(table_path)?.take(cap).read_to_string(&mut text)?;
    let table = load_roles(&text, limits)?;
    let role = table
        .roles
        .iter()
        .find(|candidate| candidate.name == role_name)
        .ok_or_else(|| CliError::NoRole(role_name.to_string()))?;
    out.write_all(render_policy(role, limits)?.as_bytes())?;
    Ok(())
}
