use crate::error::FetchError;
use crate::fetch::{post_reply, Session};
use serde::Deserialize;
use serde_json::json;


pub const REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";


pub const REVIEW_MAX_BYTES: u64 = 65_536;


pub const STATUS_OK: u16 = 200;


pub const STATUS_CREATED: u16 = 201;


pub const WRITE_VERBS: [&str; 4] = ["create", "update", "patch", "delete"];


/// Group, resource and the name shown in a refusal; the core group is the empty string.
pub const WRITE_TARGETS: [(&str, &str, &str); 4] = [
    ("", "pods", "pods"),
    ("", "nodes", "nodes"),
    ("", "secrets", "secrets"),
    ("apps", "deployments", "deployments.apps"),
];


pub const READ_TARGETS: [(&str, &str, &str); 2] = [("", "pods", "pods"), ("", "nodes", "nodes")];


pub const WILDCARD: &str = "*";


pub const LIST_VERB: &str = "list";


/// One question to the API: may the token's subject do `verb` on `resource` of `group` in every namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    pub verb: &'static str,
    pub group: &'static str,
    pub resource: &'static str,
    pub name: &'static str,
}


#[derive(Debug, Deserialize)]
pub struct ReviewStatus {
    pub allowed: bool,
}


#[derive(Debug, Deserialize)]
pub struct ReviewAnswer {
    pub status: ReviewStatus,
}


/// Every write verb on the four watched resources, then every verb on every resource.
pub fn write_permissions() -> Vec<Permission> {
    let mut permissions = WRITE_VERBS
        .iter()
        .flat_map(|verb| {
            WRITE_TARGETS
                .iter()
                .map(move |(group, resource, name)| Permission { verb, group, resource, name })
        })
        .collect::<Vec<_>>();
    permissions.push(Permission {
        verb: WILDCARD,
        group: WILDCARD,
        resource: WILDCARD,
        name: WILDCARD,
    });
    permissions
}


pub fn read_permissions() -> Vec<Permission> {
    READ_TARGETS
        .iter()
        .map(|(group, resource, name)| Permission {
            verb: LIST_VERB,
            group,
            resource,
            name,
        })
        .collect()
}


pub fn review_body(permission: &Permission) -> String {
    json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectAccessReview",
        "spec": {"resourceAttributes": {"verb": permission.verb, "group": permission.group, "resource": permission.resource}}
    })
    .to_string()
}


/// The answer is read under `REVIEW_MAX_BYTES` and the run budget, then only `status.allowed` is taken, and it is required.
pub fn is_allowed(session: &mut Session, permission: &Permission) -> Result<bool, FetchError> {
    let reply = post_reply(session, REVIEW_PATH, &review_body(permission), REVIEW_MAX_BYTES)?;
    match reply.status {
        STATUS_OK | STATUS_CREATED => {
            let answer =
                serde_json::from_slice::<ReviewAnswer>(&reply.body).map_err(|error| FetchError::ReviewMalformed { category: error.classify() })?;
            Ok(answer.status.allowed)
        }
        status => Err(FetchError::Status { status }),
    }
}


/// A writable credential is refused before any list, naming the first verb and resource found; a missing list right is refused too.
pub fn check_read_only(session: &mut Session) -> Result<(), FetchError> {
    write_permissions().iter().try_for_each(|permission| {
        if is_allowed(session, permission)? {
            Err(FetchError::WritableCredential {
                verb: permission.verb,
                resource: permission.name,
            })
        } else {
            Ok(())
        }
    })?;
    read_permissions().iter().try_for_each(|permission| {
        if is_allowed(session, permission)? {
            Ok(())
        } else {
            Err(FetchError::MissingRead { resource: permission.name })
        }
    })
}
