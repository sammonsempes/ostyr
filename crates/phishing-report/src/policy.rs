use crate::error::TriageError;
use crate::model::ReporterPolicy;


pub const MAX_INTERNAL_DOMAINS: usize = 1024;


const MAX_DOMAIN_BYTES: usize = 253;


const MAX_LABEL_BYTES: usize = 63;


fn is_ldh_label(label: &str) -> bool {
    (1..=MAX_LABEL_BYTES).contains(&label.len())
        && label.chars().all(|candidate| candidate.is_ascii_alphanumeric() || candidate == '-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}


/// An ASCII LDH domain (punycode for IDN): no trailing dot, no empty label, no label starting or ending with `-`.
pub fn is_ldh_domain(domain: &str) -> bool {
    domain.len() <= MAX_DOMAIN_BYTES && domain.split('.').all(is_ldh_label)
}


/// The policy as the caller's tenant list: at most `MAX_INTERNAL_DOMAINS` entries, each an LDH domain.
pub fn check_policy(policy: &ReporterPolicy) -> Result<(), TriageError> {
    let valid = policy.internal_domains.len() <= MAX_INTERNAL_DOMAINS && policy.internal_domains.iter().all(|domain| is_ldh_domain(domain));
    valid.then_some(()).ok_or(TriageError::PolicyRefused)
}


/// Builds a checked policy with every domain lowered by `to_ascii_lowercase`.
pub fn reporter_policy(domains: &[String]) -> Result<ReporterPolicy, TriageError> {
    let policy = ReporterPolicy {
        internal_domains: domains.iter().map(|domain| domain.to_ascii_lowercase()).collect(),
    };
    check_policy(&policy).map(|()| policy)
}


/// Exact match, never by suffix: a subdomain is listed itself.
pub fn is_internal(policy: &ReporterPolicy, domain: &str) -> bool {
    policy.internal_domains.iter().any(|listed| listed.eq_ignore_ascii_case(domain))
}
