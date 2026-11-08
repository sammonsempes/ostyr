use crate::model::{AsrChange, Decision, Evidence, Exclusion, Impact, Proposal, Reason, Scope, Selector, SelectorKind, Severity, Verdict};
use crate::path::{canonical_path, command_line_paths, covers, CanonicalPath};
use crate::policy::{policy_version, stem_of, LoadedPolicy};
use uuid::Uuid;


pub const SHA256_HEX_LENGTH: usize = 64;


pub const MAX_SELECTOR_BYTES: usize = 4096;


pub const MAX_TECHNIQUES: usize = 64;


pub const MAX_TECHNIQUE_BYTES: usize = 32;


pub const MAX_IMAGE_NAMES: usize = 64;


pub const MAX_IMAGE_NAME_BYTES: usize = 255;


pub const MAX_RULE_ID_BYTES: usize = 64;


pub const WILDCARD_SIGNER_CHARACTERS: [char; 3] = ['*', '?', '%'];


pub fn bounded_impact(impact: &Impact) -> bool {
    impact.techniques.len() <= MAX_TECHNIQUES && impact.techniques.iter().all(|technique| technique.len() <= MAX_TECHNIQUE_BYTES)
}


pub fn bounded_exclusion(exclusion: &Exclusion) -> bool {
    let images = &exclusion.evidence.observed_image_names;
    let known_hash_bytes = exclusion.evidence.known_hash.as_ref().map_or(0, String::len);
    exclusion.selector.value.len() <= MAX_SELECTOR_BYTES
        && known_hash_bytes <= MAX_SELECTOR_BYTES
        && images.len() <= MAX_IMAGE_NAMES
        && images.iter().all(|name| name.len() <= MAX_IMAGE_NAME_BYTES)
        && bounded_impact(&exclusion.impact)
}


/// Checked before anything else, so an oversized field is never echoed into a reason or the audit.
pub fn bounded(proposal: &Proposal) -> bool {
    match proposal {
        Proposal::Exclusion(exclusion) => bounded_exclusion(exclusion),
        Proposal::AsrChange(change) => change.rule_id.len() <= MAX_RULE_ID_BYTES && bounded_impact(&change.impact),
    }
}


pub fn valid_hash(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH && value.chars().all(|digit| digit.is_ascii_hexdigit())
}


pub fn is_interpreter(loaded: &LoadedPolicy, image_name: &str) -> bool {
    let file_name = image_name.rsplit(['/', '\\']).next().unwrap_or(image_name);
    let stem = stem_of(file_name);
    stem.is_empty()
        || stem.contains('~')
        || loaded.interpreter_stems.iter().any(|interpreter| {
            stem.strip_prefix(interpreter.as_str())
                .is_some_and(|rest| rest.chars().all(|digit| digit.is_ascii_digit()))
        })
}


pub fn global_image_reasons(loaded: &LoadedPolicy, names: &[String]) -> Vec<Reason> {
    if names.is_empty() {
        vec![Reason::NoObservedImage]
    } else {
        names
            .iter()
            .filter(|name| is_interpreter(loaded, name))
            .map(|name| Reason::SystemBinary { name: name.clone() })
            .collect()
    }
}


pub fn hash_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    let invalid = (!valid_hash(&exclusion.selector.value)).then_some(Reason::InvalidHash);
    let images = if exclusion.scope == Scope::Global {
        global_image_reasons(loaded, &exclusion.evidence.observed_image_names)
    } else {
        Vec::new()
    };
    invalid.into_iter().chain(images).collect()
}


pub fn location_reasons(loaded: &LoadedPolicy, path: &CanonicalPath) -> Vec<Reason> {
    let writable = loaded
        .writable
        .iter()
        .filter(|entry| covers(&entry.path, path))
        .map(|entry| Reason::UserWritableDirectory {
            directory: entry.name.clone(),
        });
    let segment = path
        .components
        .iter()
        .find(|component| loaded.segments.contains(component))
        .map(|component| Reason::UserWritableDirectory {
            directory: component.clone(),
        });
    let protected = loaded
        .protected
        .iter()
        .filter(|entry| covers(&entry.path, path))
        .map(|entry| Reason::ProtectedPath {
            directory: entry.name.clone(),
        });
    writable.chain(segment).chain(protected).collect()
}


pub fn path_reasons(loaded: &LoadedPolicy, paths: Result<Vec<CanonicalPath>, crate::model::PathForm>) -> Vec<Reason> {
    match paths {
        Err(form) => vec![Reason::NonCanonical { form }],
        Ok(found) => found.iter().flat_map(|path| location_reasons(loaded, path)).collect(),
    }
}


pub fn signer_reasons(value: &str) -> Vec<Reason> {
    if value.is_empty() || value.contains(WILDCARD_SIGNER_CHARACTERS) || value.chars().any(char::is_control) {
        vec![Reason::InvalidSigner]
    } else {
        Vec::new()
    }
}


pub fn wide_scope_reason(kind: SelectorKind) -> Reason {
    match kind {
        SelectorKind::Path => Reason::PathAtWideScope,
        SelectorKind::ProcessName => Reason::ProcessNameAtWideScope,
        SelectorKind::CommandLine => Reason::CommandLineAtWideScope,
        SelectorKind::Signer | SelectorKind::Hash => Reason::SignerAtWideScope,
    }
}


/// At global or group scope only a hash is allowed; at single endpoint scope a path form is canonical or refused.
pub fn selector_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    let Selector { kind, value } = &exclusion.selector;
    let wide = exclusion.scope != Scope::SingleEndpoint;
    match (kind, wide) {
        (SelectorKind::Hash, _) => hash_reasons(loaded, exclusion),
        (_, true) => vec![wide_scope_reason(*kind)],
        (SelectorKind::Signer, false) => signer_reasons(value),
        (SelectorKind::Path | SelectorKind::ProcessName, false) => path_reasons(loaded, canonical_path(value).map(|path| vec![path])),
        (SelectorKind::CommandLine, false) => path_reasons(loaded, command_line_paths(value)),
    }
}


pub fn evidence_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    let Evidence {
        benign_verdicts,
        distinct_days,
        role_match,
        original_severity,
        honeytoken_linked,
        signed_by_trusted,
        known_hash,
        ..
    } = &exclusion.evidence;
    let policy = &loaded.policy;
    let kind = exclusion.selector.kind;
    let hash_known = known_hash.is_some() || kind == SelectorKind::Hash;
    let names_a_file = !matches!(kind, SelectorKind::Hash | SelectorKind::Signer);
    [
        (*benign_verdicts < policy.min_benign_verdicts).then_some(Reason::TooFewVerdicts {
            have: *benign_verdicts,
            need: policy.min_benign_verdicts,
        }),
        (*distinct_days < policy.min_distinct_days).then_some(Reason::TooFewDays {
            have: *distinct_days,
            need: policy.min_distinct_days,
        }),
        (exclusion.scope == Scope::SingleEndpoint && !role_match).then_some(Reason::NoRoleMatch),
        (*original_severity == Severity::Critical).then_some(Reason::CriticalAlert),
        honeytoken_linked.then_some(Reason::HoneytokenLinked),
        (!signed_by_trusted && !hash_known).then_some(Reason::UnsignedWithoutHash),
        (!signed_by_trusted && names_a_file).then_some(Reason::UnsignedPath),
        (exclusion.lifetime_days > policy.max_lifetime_days).then_some(Reason::LifetimeTooLong {
            days: exclusion.lifetime_days,
            max: policy.max_lifetime_days,
        }),
    ]
    .into_iter()
    .flatten()
    .collect()
}


/// The narrower alternative goes into the reason: a known hash beats any other selector, one endpoint seen beats a wider scope.
pub fn narrowest_reasons(exclusion: &Exclusion) -> Vec<Reason> {
    let narrower_selector = exclusion
        .evidence
        .known_hash
        .as_ref()
        .filter(|_| exclusion.selector.kind != SelectorKind::Hash)
        .map(|hash| Reason::NarrowerSelector { hash: hash.clone() });
    let narrower_scope = (exclusion.scope != Scope::SingleEndpoint && exclusion.evidence.distinct_endpoints <= 1).then_some(Reason::NarrowerScope);
    narrower_selector.into_iter().chain(narrower_scope).collect()
}


/// A technique with at most one detection would be left with none by the change; an unknown technique counts as none.
pub fn impact_reasons(impact: &Impact) -> Vec<Reason> {
    impact
        .techniques
        .iter()
        .filter(|technique| impact.detections.get(*technique).copied().unwrap_or(0) <= 1)
        .map(|technique| Reason::CoverageLoss {
            technique: technique.clone(),
        })
        .collect()
}


pub fn exclusion_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    [
        selector_reasons(loaded, exclusion),
        evidence_reasons(loaded, exclusion),
        narrowest_reasons(exclusion),
        impact_reasons(&exclusion.impact),
    ]
    .concat()
}


pub fn asr_rule_reasons(loaded: &LoadedPolicy, change: &AsrChange) -> Vec<Reason> {
    match Uuid::parse_str(&change.rule_id) {
        Err(_) => vec![Reason::InvalidAsrRuleId],
        Ok(rule_id) => (loaded.policy.critical_asr_rules.contains(&rule_id) && change.new_state != crate::model::AsrState::Block)
            .then_some(Reason::CriticalAsrRule { rule_id })
            .into_iter()
            .collect(),
    }
}


pub fn proposal_reasons(loaded: &LoadedPolicy, proposal: &Proposal) -> Vec<Reason> {
    match proposal {
        Proposal::Exclusion(exclusion) => exclusion_reasons(loaded, exclusion),
        Proposal::AsrChange(change) => [asr_rule_reasons(loaded, change), impact_reasons(&change.impact)].concat(),
    }
}


pub fn verdict_of(loaded: &LoadedPolicy, found: Vec<Reason>) -> Verdict {
    Verdict {
        version: policy_version(loaded),
        decision: if found.is_empty() { Decision::Accepted } else { Decision::Refused },
        reasons: found,
    }
}


/// Deterministic and pure: the same policy and proposal always give the same verdict.
pub fn validate(loaded: &LoadedPolicy, proposal: &Proposal) -> Verdict {
    verdict_of(
        loaded,
        if bounded(proposal) {
            proposal_reasons(loaded, proposal)
        } else {
            vec![Reason::InputTooLarge]
        },
    )
}
