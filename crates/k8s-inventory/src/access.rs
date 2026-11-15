use crate::error::FetchError;
use crate::fetch::{get_reply, post_reply, Session, STATUS_OK};
use crate::text::valid_dns_label;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::error::Category;
use serde_json::json;
use serde_json::value::RawValue;
use std::borrow::Cow;


pub const REVIEW_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";


pub const RULES_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews";


pub const NAMESPACES_PATH: &str = "/api/v1/namespaces";


pub const REVIEW_MAX_BYTES: u64 = 65_536;


pub const NAMESPACE_BYTES_EACH: u64 = 16_384;


pub const STATUS_CREATED: u16 = 201;


pub const MAX_RULES: usize = 512;


pub const MAX_ENTRIES: usize = 256;


pub const MAX_SHOWN: usize = 64;


pub const READ_VERBS: [&str; 3] = ["get", "list", "watch"];


pub const NON_RESOURCE_VERB: &str = "get";


/// The kube-apiserver `/logs` handler serves the control-plane host's `/var/log`.
pub const PROTECTED_URLS: [&str; 2] = ["/logs", "/debug"];


pub const CREATE_VERB: &str = "create";


pub const WILDCARD: char = '*';


pub const SECRETS: &str = "secrets";


pub const TOKEN_SUBRESOURCE: &str = "serviceaccounts/token";


/// `get` on `nodes/log` returns the node's whole `/var/log` through the kubelet; the stock `view` role does not grant it.
pub const NODE_LOG: &str = "nodes/log";


/// `get` on `nodes/configz` returns the whole KubeletConfiguration, which can carry `staticPodURLHeader` credentials.
pub const NODE_CONFIGZ: &str = "nodes/configz";


/// Subresources whose read verbs reach the kubelet or a pod stream: `get` on `nodes/proxy` runs commands in any container.
pub const ACTIVE_SUFFIXES: [&str; 4] = ["/proxy", "/exec", "/attach", "/portforward"];


/// The only write the token may keep: asking the API what it may do (`system:basic-user`), as group and resource.
pub const SELF_REVIEWS: [(&str, &str); 3] = [
    ("authorization.k8s.io", "selfsubjectaccessreviews"),
    ("authorization.k8s.io", "selfsubjectrulesreviews"),
    ("authentication.k8s.io", "selfsubjectreviews"),
];


pub const READ_TARGETS: [(&str, &str, &str); 2] = [("", "pods", "pods"), ("", "nodes", "nodes")];


pub const LIST_VERB: &str = "list";


/// One question to the API: may the token's subject list `resource` of `group` in every namespace.
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


#[derive(Deserialize)]
pub struct RulesAnswer<'a> {
    #[serde(borrow)]
    status: RulesStatus<'a>,
}


#[derive(Deserialize)]
pub struct RulesStatus<'a> {
    #[serde(borrow, rename = "resourceRules")]
    resource_rules: Option<&'a RawValue>,
    #[serde(borrow, rename = "nonResourceRules")]
    non_resource_rules: Option<&'a RawValue>,
    incomplete: Option<bool>,
    #[serde(rename = "evaluationError")]
    evaluation_error: Option<IgnoredAny>,
}


#[derive(Deserialize)]
pub struct RawRule<'a> {
    #[serde(borrow)]
    verbs: Option<&'a RawValue>,
    #[serde(borrow, rename = "apiGroups")]
    api_groups: Option<&'a RawValue>,
    #[serde(borrow)]
    resources: Option<&'a RawValue>,
    #[serde(borrow, rename = "resourceNames")]
    resource_names: Option<&'a RawValue>,
    #[serde(borrow, rename = "nonResourceURLs")]
    urls: Option<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct NamespaceList<'a> {
    #[serde(borrow)]
    items: &'a RawValue,
    metadata: Option<NamespaceListMetadata<'a>>,
}


#[derive(Deserialize)]
pub struct NamespaceListMetadata<'a> {
    #[serde(borrow, rename = "continue")]
    next: Option<Cow<'a, str>>,
}


#[derive(Deserialize)]
pub struct NamespaceItem {
    metadata: NamespaceMetadata,
}


#[derive(Deserialize)]
pub struct NamespaceMetadata {
    name: String,
}


/// A verb, group and resource named in a refusal, cut for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offence {
    pub verb: String,
    pub group: String,
    pub resource: String,
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


pub fn rules_body(namespace: &str) -> String {
    json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {"namespace": namespace}
    })
    .to_string()
}


pub fn malformed(error: serde_json::Error) -> FetchError {
    FetchError::ReviewMalformed { category: error.classify() }
}


/// Printable ASCII only and at most `MAX_SHOWN` characters, with a marker when cut: an API text never reaches an error raw.
pub fn shown(text: &str) -> String {
    let kept = text
        .chars()
        .take(MAX_SHOWN)
        .map(|character| if character.is_ascii_graphic() { character } else { '?' })
        .collect::<String>();
    if text.chars().count() > MAX_SHOWN {
        format!("{kept}...")
    } else {
        kept
    }
}


/// The answer is read under `REVIEW_MAX_BYTES` and the run budget, then only `status.allowed` is taken, and it is required.
pub fn is_allowed(session: &mut Session, permission: &Permission) -> Result<bool, FetchError> {
    let reply = post_reply(session, REVIEW_PATH, &review_body(permission), REVIEW_MAX_BYTES)?;
    match reply.status {
        STATUS_OK | STATUS_CREATED => Ok(serde_json::from_slice::<ReviewAnswer>(&reply.body).map_err(malformed)?.status.allowed),
        status => Err(FetchError::Status { status }),
    }
}


/// A JSON array counted without allocating (`IgnoredAny` is zero-sized): refused above `max` before any element is built.
pub fn count_of(raw: Option<&RawValue>, what: &'static str, max: usize) -> Result<usize, FetchError> {
    let count = match raw {
        Some(text) => serde_json::from_str::<Vec<IgnoredAny>>(text.get()).map_err(malformed)?.len(),
        None => 0,
    };
    if count > max {
        Err(FetchError::TooMany { what, max })
    } else {
        Ok(count)
    }
}


pub fn strings_of(raw: Option<&RawValue>, what: &'static str) -> Result<Vec<String>, FetchError> {
    count_of(raw, what, MAX_ENTRIES)?;
    raw.map_or_else(
        || Ok(Vec::new()),
        |text| serde_json::from_str::<Vec<String>>(text.get()).map_err(malformed),
    )
}


pub fn rules_of<'a>(raw: Option<&'a RawValue>, what: &'static str) -> Result<Vec<RawRule<'a>>, FetchError> {
    count_of(raw, what, MAX_RULES)?;
    raw.map_or_else(
        || Ok(Vec::new()),
        |text| {
            serde_json::from_str::<Vec<&RawValue>>(text.get())
                .map_err(malformed)?
                .into_iter()
                .map(|rule| serde_json::from_str::<RawRule>(rule.get()).map_err(malformed))
                .collect()
        },
    )
}


/// `create` on exactly the self-review resources, and nothing else in the rule.
pub fn is_self_review(verb: &str, groups: &[String], resources: &[String]) -> bool {
    verb == CREATE_VERB
        && !groups.is_empty()
        && !resources.is_empty()
        && groups.iter().all(|group| {
            resources.iter().all(|resource| {
                SELF_REVIEWS
                    .iter()
                    .any(|(allowed_group, allowed_resource)| group == allowed_group && resource == allowed_resource)
            })
        })
}


pub fn offence_of(verb: &str, groups: &[String], resources: &[String]) -> Offence {
    Offence {
        verb: shown(verb),
        group: groups.first().map_or_else(String::new, |group| shown(group)),
        resource: resources.first().map_or_else(String::new, |resource| shown(resource)),
    }
}


/// A read verb on this resource still gives a write or a credential (RBAC good practices, kubelet authorization docs).
pub fn grants_more_than_reading(groups: &[String], resource: &str) -> bool {
    resource.contains(WILDCARD)
        || (resource == SECRETS && groups.iter().any(String::is_empty))
        || resource == TOKEN_SUBRESOURCE
        || resource == NODE_LOG
        || resource == NODE_CONFIGZ
        || ACTIVE_SUFFIXES.iter().any(|suffix| resource.ends_with(suffix))
}


/// A rule naming `*` in its groups or one `grants_more_than_reading` resource is an offence whatever its verbs.
pub fn reach_offence(verbs: &[String], groups: &[String], resources: &[String]) -> Option<Offence> {
    let verb = verbs.first().map_or("", String::as_str);
    let wild_group = groups.iter().find(|group| group.contains(WILDCARD));
    let risky = resources.iter().find(|resource| grants_more_than_reading(groups, resource));
    match (wild_group, risky) {
        (Some(group), _) => Some(offence_of(verb, std::slice::from_ref(group), resources)),
        (None, Some(resource)) => Some(offence_of(verb, groups, std::slice::from_ref(resource))),
        (None, None) => None,
    }
}


/// Every verb outside `get`, `list`, `watch` is an offence, `*` included, except the self-review rules; then the resources a read verb abuses.
pub fn resource_offence(rule: &RawRule) -> Result<Option<Offence>, FetchError> {
    let verbs = strings_of(rule.verbs, "verbs")?;
    let groups = strings_of(rule.api_groups, "apiGroups")?;
    let resources = strings_of(rule.resources, "resources")?;
    count_of(rule.resource_names, "resourceNames", MAX_ENTRIES)?;
    let by_verb = verbs
        .iter()
        .find(|verb| !READ_VERBS.contains(&verb.as_str()) && !is_self_review(verb, &groups, &resources))
        .map(|verb| offence_of(verb, &groups, &resources));
    Ok(by_verb.or_else(|| reach_offence(&verbs, &groups, &resources)))
}


/// A non-resource URL names `/logs` or `/debug`, anything under them, or a trailing-`*` glob (every trailing `*` removed) covering them.
pub fn covers_logs(url: &str) -> bool {
    let glob_prefix = url.trim_end_matches(WILDCARD);
    let is_glob = glob_prefix.len() < url.len();
    PROTECTED_URLS.iter().any(|protected| {
        url == *protected || url.starts_with(&format!("{protected}/")) || (is_glob && format!("{protected}/").starts_with(glob_prefix))
    })
}


/// A non-resource rule may only `get`, and not on `/logs` or a glob covering it.
pub fn non_resource_offence(rule: &RawRule) -> Result<Option<Offence>, FetchError> {
    let verbs = strings_of(rule.verbs, "verbs")?;
    let urls = strings_of(rule.urls, "nonResourceURLs")?;
    let by_verb = verbs
        .iter()
        .find(|verb| verb.as_str() != NON_RESOURCE_VERB)
        .map(|verb| offence_of(verb, &[], &urls));
    let by_url = urls
        .iter()
        .find(|url| covers_logs(url))
        .map(|url| offence_of(NON_RESOURCE_VERB, &[], std::slice::from_ref(url)));
    Ok(by_verb.or(by_url))
}


pub fn first_offence(rules: &[RawRule], judge: fn(&RawRule) -> Result<Option<Offence>, FetchError>) -> Result<Option<Offence>, FetchError> {
    rules
        .iter()
        .try_fold(None, |found: Option<Offence>, rule| if found.is_some() { Ok(found) } else { judge(rule) })
}


/// The rules of one namespace pass only if the review is complete and error free and every rule is read-only; the first offence is named.
pub fn check_status(namespace: &str, status: &RulesStatus) -> Result<(), FetchError> {
    if status.incomplete.unwrap_or(false) {
        Err(FetchError::RulesUnverifiable {
            namespace: namespace.to_owned(),
            reason: "the rule list is incomplete",
        })?;
    }
    if status.evaluation_error.is_some() {
        Err(FetchError::RulesUnverifiable {
            namespace: namespace.to_owned(),
            reason: "the review reported an evaluation error",
        })?;
    }
    let resource_rules = rules_of(status.resource_rules, "resourceRules")?;
    let non_resource_rules = rules_of(status.non_resource_rules, "nonResourceRules")?;
    let offence = match first_offence(&resource_rules, resource_offence)? {
        Some(found) => Some(found),
        None => first_offence(&non_resource_rules, non_resource_offence)?,
    };
    offence.map_or(Ok(()), |found| {
        Err(FetchError::WritableCredential {
            verb: found.verb,
            group: found.group,
            resource: found.resource,
        })
    })
}


pub fn review_rules(session: &mut Session, namespace: &str) -> Result<(), FetchError> {
    let reply = post_reply(session, RULES_PATH, &rules_body(namespace), REVIEW_MAX_BYTES)?;
    match reply.status {
        STATUS_OK | STATUS_CREATED => check_status(namespace, &serde_json::from_slice::<RulesAnswer>(&reply.body).map_err(malformed)?.status),
        status => Err(FetchError::Status { status }),
    }
}


/// Namespace names from one list request of `limit=max`: a continue token or more than `max` items is `TooMany`, an invalid name is refused.
pub fn namespaces_of(session: &mut Session, max: usize) -> Result<Vec<String>, FetchError> {
    let limit = max.to_string();
    let cap = NAMESPACE_BYTES_EACH.saturating_mul(max as u64);
    let reply = get_reply(session, NAMESPACES_PATH, &[("limit", limit.as_str())], cap)?;
    if reply.status != STATUS_OK {
        Err(FetchError::Status { status: reply.status })?;
    }
    let list = serde_json::from_slice::<NamespaceList>(&reply.body).map_err(malformed)?;
    if list.metadata.and_then(|metadata| metadata.next).is_some_and(|next| !next.is_empty()) {
        Err(FetchError::TooMany { what: "namespaces", max })?;
    }
    count_of(Some(list.items), "namespaces", max)?;
    let items = serde_json::from_str::<Vec<NamespaceItem>>(list.items.get()).map_err(malformed)?;
    items.into_iter().map(|item| named(item.metadata.name)).collect()
}


pub fn named(name: String) -> Result<String, FetchError> {
    if valid_dns_label(&name) {
        Ok(name)
    } else {
        Err(FetchError::ReviewMalformed { category: Category::Data })
    }
}


/// The rules of every namespace are reviewed at every run (a namespace made later is covered); the first write right refuses the run.
pub fn check_rules(session: &mut Session, max_namespaces: usize) -> Result<(), FetchError> {
    let namespaces = namespaces_of(session, max_namespaces)?;
    if namespaces.is_empty() {
        Err(FetchError::MissingRead { resource: "namespaces" })?;
    }
    namespaces.iter().try_for_each(|namespace| review_rules(session, namespace))
}


/// The list rights first (`MissingRead`), then the rules review of every namespace; nothing is listed before both pass.
pub fn check_read_only(session: &mut Session, max_namespaces: usize) -> Result<(), FetchError> {
    read_permissions().iter().try_for_each(|permission| {
        if is_allowed(session, permission)? {
            Ok(())
        } else {
            Err(FetchError::MissingRead { resource: permission.name })
        }
    })?;
    check_rules(session, max_namespaces)
}
