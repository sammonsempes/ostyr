use crate::error::AuthError;
use crate::types::{RoleCatalog, RoleSet};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::Read;


pub const ROLE_READER: &str = "reader";


pub const ROLE_ANALYST: &str = "analyst";


pub const ROLE_RESPONDER: &str = "responder";


pub const ROLE_ADMINISTRATOR: &str = "administrator";


pub const ROLE_AUDITOR: &str = "auditor";


pub const PERMISSION_EVENTS_READ: &str = "events.read";


pub const PERMISSION_ALERTS_TRIAGE: &str = "alerts.triage";


pub const PERMISSION_RESPONSE_EXECUTE: &str = "response.execute";


pub const PERMISSION_AUDIT_READ: &str = "audit.read";


pub const PERMISSION_USERS_MANAGE: &str = "users.manage";


pub const PERMISSION_CONFIG_MANAGE: &str = "config.manage";


pub const MFA_REQUIRED_ROLES: [&str; 1] = [ROLE_ADMINISTRATOR];


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRole {
    pub name: String,
    pub permissions: BTreeSet<String>,
}


pub fn permission_set(permissions: &[&str]) -> BTreeSet<String> {
    permissions.iter().map(|permission| (*permission).to_owned()).collect()
}


pub fn builtin_catalog() -> RoleCatalog {
    let reader = [PERMISSION_EVENTS_READ];
    let analyst = [PERMISSION_EVENTS_READ, PERMISSION_ALERTS_TRIAGE];
    let responder = [PERMISSION_EVENTS_READ, PERMISSION_ALERTS_TRIAGE, PERMISSION_RESPONSE_EXECUTE];
    let administrator = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_RESPONSE_EXECUTE,
        PERMISSION_USERS_MANAGE,
        PERMISSION_CONFIG_MANAGE,
    ];
    let auditor = [PERMISSION_EVENTS_READ, PERMISSION_AUDIT_READ];
    [
        (ROLE_READER, permission_set(&reader)),
        (ROLE_ANALYST, permission_set(&analyst)),
        (ROLE_RESPONDER, permission_set(&responder)),
        (ROLE_ADMINISTRATOR, permission_set(&administrator)),
        (ROLE_AUDITOR, permission_set(&auditor)),
    ]
    .into_iter()
    .map(|(name, permissions)| (name.to_owned(), permissions))
    .collect()
}


pub fn add_custom_roles(catalog: &mut RoleCatalog, roles: Vec<CustomRole>) -> Result<(), AuthError> {
    roles.into_iter().try_for_each(|role| match catalog.contains_key(&role.name) {
        true => Err(AuthError::BuiltInRole(role.name)),
        false => {
            catalog.insert(role.name, role.permissions);
            Ok(())
        }
    })
}


pub fn load_catalog<Input: Read>(input: Input) -> Result<RoleCatalog, AuthError> {
    let roles: Vec<CustomRole> = serde_json::from_reader(input)?;
    let mut catalog = builtin_catalog();
    add_custom_roles(&mut catalog, roles)?;
    Ok(catalog)
}


pub fn is_allowed(catalog: &RoleCatalog, roles: &RoleSet, permission: &str) -> bool {
    roles
        .iter()
        .filter_map(|role| catalog.get(role))
        .any(|permissions| permissions.contains(permission))
}


pub fn requires_mfa(roles: &RoleSet) -> bool {
    MFA_REQUIRED_ROLES.iter().any(|required| roles.contains(*required))
}


pub fn check_roles(catalog: &RoleCatalog, roles: &RoleSet) -> Result<(), AuthError> {
    roles.iter().try_for_each(|role| {
        catalog
            .contains_key(role)
            .then_some(())
            .ok_or_else(|| AuthError::UnknownRole(role.clone()))
    })
}
