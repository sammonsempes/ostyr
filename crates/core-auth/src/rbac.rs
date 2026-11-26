use crate::error::{AuthError, RolesError};
use crate::types::{RoleCatalog, RoleSet};
use serde::Deserialize;
use serde_json::Value;
use std::collections::btree_map::Entry;
use std::collections::BTreeSet;
use std::io::Read;


pub const ROLE_READER: &str = "reader";


pub const ROLE_ANALYST: &str = "analyst";


pub const ROLE_RESPONDER: &str = "responder";


pub const ROLE_ADMINISTRATOR: &str = "administrator";


pub const ROLE_AUDITOR: &str = "auditor";


pub const PERMISSION_EVENTS_READ: &str = "events.read";


pub const PERMISSION_ALERTS_READ: &str = "alerts.read";


pub const PERMISSION_CASES_READ: &str = "cases.read";


pub const PERMISSION_CASES_WRITE: &str = "cases.write";


pub const PERMISSION_CMDB_READ: &str = "cmdb.read";


pub const PERMISSION_ATTACK_PATHS_READ: &str = "attack_paths.read";


pub const PERMISSION_GRC_READ: &str = "grc.read";


pub const PERMISSION_PLAYBOOKS_READ: &str = "playbooks.read";


pub const PERMISSION_ONCALL_READ: &str = "oncall.read";


pub const PERMISSION_ONCALL_ACKNOWLEDGE: &str = "oncall.acknowledge";


pub const PERMISSION_STATUS_WRITE: &str = "status.write";


pub const PERMISSION_ALERTS_TRIAGE: &str = "alerts.triage";


pub const PERMISSION_RESPONSE_EXECUTE: &str = "response.execute";


pub const PERMISSION_AUDIT_READ: &str = "audit.read";


pub const PERMISSION_USERS_MANAGE: &str = "users.manage";


pub const PERMISSION_CONFIG_MANAGE: &str = "config.manage";


pub const PERMISSION_ROLES_MANAGE: &str = "roles.manage";


pub const PERMISSION_AUDIT_EXPORT: &str = "audit.export";


pub const POLICY_WEBAUTHN_REQUIRED: &str = "policy.webauthn_required";


pub const POLICY_PREFIX: &str = "policy.";


pub const MAX_ROLES_FILE_BYTES: u64 = 65_536;


pub const MAX_CUSTOM_ROLES: usize = 64;


pub const MAX_ROLE_PERMISSIONS: usize = 128;


pub const MAX_ROLE_NAME_BYTES: usize = 64;


pub const PRIVILEGED_PERMISSIONS: [&str; 4] = [
    PERMISSION_USERS_MANAGE,
    PERMISSION_CONFIG_MANAGE,
    PERMISSION_ROLES_MANAGE,
    PERMISSION_AUDIT_EXPORT,
];


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
    let analyst = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_CASES_READ,
        PERMISSION_CASES_WRITE,
        PERMISSION_CMDB_READ,
        PERMISSION_ATTACK_PATHS_READ,
        PERMISSION_GRC_READ,
        PERMISSION_PLAYBOOKS_READ,
        PERMISSION_ONCALL_READ,
        PERMISSION_ONCALL_ACKNOWLEDGE,
    ];
    let responder = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_CASES_READ,
        PERMISSION_CASES_WRITE,
        PERMISSION_CMDB_READ,
        PERMISSION_ONCALL_READ,
        PERMISSION_ONCALL_ACKNOWLEDGE,
        PERMISSION_STATUS_WRITE,
        PERMISSION_RESPONSE_EXECUTE,
    ];
    let administrator = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_CASES_READ,
        PERMISSION_CASES_WRITE,
        PERMISSION_CMDB_READ,
        PERMISSION_ATTACK_PATHS_READ,
        PERMISSION_GRC_READ,
        PERMISSION_PLAYBOOKS_READ,
        PERMISSION_ONCALL_READ,
        PERMISSION_ONCALL_ACKNOWLEDGE,
        PERMISSION_STATUS_WRITE,
        PERMISSION_RESPONSE_EXECUTE,
        PERMISSION_USERS_MANAGE,
        PERMISSION_CONFIG_MANAGE,
        PERMISSION_ROLES_MANAGE,
    ];
    let auditor = [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_CASES_READ,
        PERMISSION_CMDB_READ,
        PERMISSION_ATTACK_PATHS_READ,
        PERMISSION_GRC_READ,
        PERMISSION_PLAYBOOKS_READ,
        PERMISSION_ONCALL_READ,
        PERMISSION_AUDIT_READ,
    ];
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


/// A role or permission name: 1 to 64 bytes of `[a-z0-9._-]`, no leading `-`.
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_ROLE_NAME_BYTES).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-'))
}


pub fn check_role(index: usize, role: &CustomRole) -> Result<(), RolesError> {
    if !valid_name(&role.name) {
        Err(RolesError::InvalidRoleName { index })
    } else if role.permissions.len() > MAX_ROLE_PERMISSIONS {
        Err(RolesError::TooManyPermissions { max: MAX_ROLE_PERMISSIONS })
    } else if role.permissions.iter().any(|permission| !valid_name(permission)) {
        Err(RolesError::InvalidPermissionName { index })
    } else if role
        .permissions
        .iter()
        .any(|permission| permission.starts_with(POLICY_PREFIX) && permission != POLICY_WEBAUTHN_REQUIRED)
    {
        Err(RolesError::UnknownPolicy { index })
    } else {
        Ok(())
    }
}


pub fn add_custom_roles(catalog: &mut RoleCatalog, roles: Vec<CustomRole>) -> Result<(), AuthError> {
    let builtin = builtin_catalog();
    roles.into_iter().enumerate().try_for_each(|(index, role)| {
        check_role(index, &role)?;
        if builtin.contains_key(&role.name) {
            Err(AuthError::BuiltInRole(role.name))
        } else {
            match catalog.entry(role.name) {
                Entry::Occupied(taken) => Err(AuthError::Roles(RolesError::DuplicateRole(taken.key().clone()))),
                Entry::Vacant(free) => {
                    free.insert(role.permissions);
                    Ok(())
                }
            }
        }
    })
}


/// The error of a roles document with its cause cut to a category and a position: never the text that failed.
pub fn syntax_error(error: &serde_json::Error) -> RolesError {
    RolesError::Syntax {
        category: format!("{:?}", error.classify()),
        line: error.line(),
        column: error.column(),
    }
}


/// Counts the roles and the permissions of each before the typed parse; the file is already capped, so this pass is bounded by it.
pub fn count_roles(bytes: &[u8]) -> Result<(), RolesError> {
    let document: Value = serde_json::from_slice(bytes).map_err(|error| syntax_error(&error))?;
    match document.as_array() {
        Some(roles) if roles.len() > MAX_CUSTOM_ROLES => Err(RolesError::TooManyRoles { max: MAX_CUSTOM_ROLES }),
        Some(roles) => roles.iter().try_for_each(|role| {
            if role
                .get("permissions")
                .and_then(Value::as_array)
                .is_some_and(|permissions| permissions.len() > MAX_ROLE_PERMISSIONS)
            {
                Err(RolesError::TooManyPermissions { max: MAX_ROLE_PERMISSIONS })
            } else {
                Ok(())
            }
        }),
        None => Ok(()),
    }
}


/// The catalog of the roles document: read at most `MAX_ROLES_FILE_BYTES`, counted, then parsed; every refusal has fixed text.
pub fn load_catalog<Input: Read>(input: Input) -> Result<RoleCatalog, AuthError> {
    let mut bytes = Vec::new();
    input.take(MAX_ROLES_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    parse_catalog(&bytes)
}


/// The same refusals as `load_catalog` for bytes already read (core-api digests the very bytes it parses).
pub fn parse_catalog(bytes: &[u8]) -> Result<RoleCatalog, AuthError> {
    if bytes.len() as u64 > MAX_ROLES_FILE_BYTES {
        Err(AuthError::Roles(RolesError::TooLarge { max: MAX_ROLES_FILE_BYTES }))
    } else {
        count_roles(bytes)?;
        let roles: Vec<CustomRole> = serde_json::from_slice(bytes).map_err(|error| syntax_error(&error))?;
        let mut catalog = builtin_catalog();
        add_custom_roles(&mut catalog, roles)?;
        Ok(catalog)
    }
}


pub fn is_allowed(catalog: &RoleCatalog, roles: &RoleSet, permission: &str) -> bool {
    roles
        .iter()
        .filter_map(|role| catalog.get(role))
        .any(|permissions| permissions.contains(permission))
}


pub fn requires_mfa(catalog: &RoleCatalog, roles: &RoleSet) -> bool {
    PRIVILEGED_PERMISSIONS.iter().any(|privileged| is_allowed(catalog, roles, privileged))
}


pub fn webauthn_required(catalog: &RoleCatalog, roles: &RoleSet) -> bool {
    is_allowed(catalog, roles, POLICY_WEBAUTHN_REQUIRED)
}


pub fn check_roles(catalog: &RoleCatalog, roles: &RoleSet) -> Result<(), AuthError> {
    roles.iter().try_for_each(|role| {
        catalog
            .contains_key(role)
            .then_some(())
            .ok_or_else(|| AuthError::UnknownRole(role.clone()))
    })
}
