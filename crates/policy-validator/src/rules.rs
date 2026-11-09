use crate::model::{
    AsrChange, Decision, Evidence, Exclusion, Impact, ObservedImage, Proposal, Reason, Scope, Selector, SelectorKind, Severity, Verdict,
};
use crate::path::{canonical_path, command_line_paths, covers, CanonicalPath, Flavour};
use crate::policy::{policy_version, stem_of, LoadedPolicy};
use uuid::Uuid;


pub const SHA256_HEX_LENGTH: usize = 64;


pub const MAX_SELECTOR_BYTES: usize = 4096;


pub const MAX_TECHNIQUES: usize = 64;


pub const MAX_TECHNIQUE_BYTES: usize = 32;


pub const MAX_IMAGE_NAMES: usize = 64;


pub const MAX_IMAGE_NAME_BYTES: usize = 255;


pub const MAX_RULE_ID_BYTES: usize = 64;


pub fn bounded_impact(impact: &Impact) -> bool {
    impact.techniques.len() <= MAX_TECHNIQUES
        && impact.techniques.iter().all(|technique| technique.len() <= MAX_TECHNIQUE_BYTES)
        && impact.detections.len() <= MAX_TECHNIQUES
        && impact.detections.keys().all(|technique| technique.len() <= MAX_TECHNIQUE_BYTES)
}


pub fn bounded_image(image: &ObservedImage) -> bool {
    image.path.len() <= MAX_SELECTOR_BYTES
        && image.sha256.len() <= MAX_IMAGE_NAME_BYTES
        && image.name.len() <= MAX_IMAGE_NAME_BYTES
        && image.original_file_name.as_ref().is_none_or(|name| name.len() <= MAX_IMAGE_NAME_BYTES)
}


pub fn bounded_exclusion(exclusion: &Exclusion) -> bool {
    let images = &exclusion.evidence.observed_images;
    let known_hash_bytes = exclusion.evidence.known_hash.as_ref().map_or(0, String::len);
    exclusion.selector.value.len() <= MAX_SELECTOR_BYTES
        && known_hash_bytes <= MAX_SELECTOR_BYTES
        && images.len() <= MAX_IMAGE_NAMES
        && images.iter().all(bounded_image)
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


pub const STEM_SEPARATORS: [char; 3] = ['-', '_', '+'];


pub fn stem_matches(stem: &str, listed: &str) -> bool {
    stem.strip_prefix(listed)
        .is_some_and(|rest| rest.starts_with(STEM_SEPARATORS) || rest.chars().all(|digit| digit.is_ascii_digit()))
}


pub fn listed_stem<'a>(stems: &'a [String], file_name: &str) -> Option<&'a String> {
    let stem = stem_of(file_name);
    stems.iter().find(|listed| stem_matches(&stem, listed))
}


pub fn listed_position(stems: &[String], file_name: &str) -> Option<usize> {
    let stem = stem_of(file_name);
    stems.iter().position(|listed| stem_matches(&stem, listed))
}


pub fn file_name_of(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}


pub fn is_interpreter(loaded: &LoadedPolicy, image_name: &str) -> bool {
    let stem = stem_of(file_name_of(image_name));
    stem.is_empty() || stem.contains('~') || listed_stem(&loaded.interpreter_stems, file_name_of(image_name)).is_some()
}


pub fn image_file_names(image: &ObservedImage) -> Vec<&str> {
    [Some(image.name.as_str()), Some(image.path.as_str()), image.original_file_name.as_deref()]
        .into_iter()
        .flatten()
        .collect()
}


pub fn sensor_position(loaded: &LoadedPolicy, image: &ObservedImage) -> Option<usize> {
    image_file_names(image)
        .iter()
        .find_map(|name| listed_position(&loaded.sensor_stems, file_name_of(name)))
}


pub fn is_system_image(loaded: &LoadedPolicy, image: &ObservedImage) -> bool {
    image.os_component || image_file_names(image).iter().any(|name| is_interpreter(loaded, name))
}


pub fn sensor_reason(loaded: &LoadedPolicy, image: &ObservedImage) -> Option<Reason> {
    match sensor_position(loaded, image) {
        Some(index) => Some(Reason::ListedSecuritySensor { index }),
        None => image.security_sensor.then(|| Reason::SecuritySensor { name: image.name.clone() }),
    }
}


pub fn image_reason(loaded: &LoadedPolicy, image: &ObservedImage) -> Vec<Reason> {
    let name = image.name.clone();
    [
        sensor_reason(loaded, image),
        is_system_image(loaded, image).then(|| Reason::SystemBinary { name: name.clone() }),
        image.writable_by_non_admin.then_some(Reason::WritableByNonAdmin { name }),
    ]
    .into_iter()
    .flatten()
    .collect()
}


/// Platform evidence decides what a file is: a sensor, a system image or a writable one is refused at every scope.
pub fn image_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    let images = &exclusion.evidence.observed_images;
    if images.is_empty() {
        vec![Reason::NoObservedImage]
    } else {
        images.iter().flat_map(|image| image_reason(loaded, image)).collect()
    }
}


pub fn hash_reasons(exclusion: &Exclusion) -> Vec<Reason> {
    (!valid_hash(&exclusion.selector.value))
        .then_some(Reason::InvalidHash)
        .into_iter()
        .collect()
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
            list: entry.list.to_owned(),
            index: entry.index,
        });
    writable.chain(segment).chain(protected).collect()
}


pub fn path_reasons(loaded: &LoadedPolicy, paths: Result<Vec<CanonicalPath>, crate::model::PathForm>) -> Vec<Reason> {
    match paths {
        Err(form) => vec![Reason::NonCanonical { form }],
        Ok(found) => found.iter().flat_map(|path| location_reasons(loaded, path)).collect(),
    }
}


pub fn file_sensor_reasons(loaded: &LoadedPolicy, path: &str) -> Vec<Reason> {
    [
        listed_position(&loaded.sensor_stems, file_name_of(path)).map(|index| Reason::ListedSecuritySensor { index }),
        listed_stem(&loaded.tool_stems, file_name_of(path)).map(|listed| Reason::ServiceControlInCommandLine { name: listed.clone() }),
    ]
    .into_iter()
    .flatten()
    .collect()
}


pub fn same_path(left: &CanonicalPath, right: &CanonicalPath) -> bool {
    left.flavour == right.flavour
        && left.drive == right.drive
        && match left.flavour {
            Flavour::Windows => left.components == right.components,
            Flavour::Posix => left.exact == right.exact,
        }
}


pub fn is_strict_ancestor(directory: &CanonicalPath, path: &CanonicalPath) -> bool {
    covers(directory, path) && directory.components.len() < path.components.len()
}


pub fn image_path(image: &ObservedImage) -> Option<CanonicalPath> {
    canonical_path(&image.path).ok()
}


pub fn is_image_path(images: &[ObservedImage], path: &CanonicalPath) -> bool {
    images.iter().filter_map(image_path).any(|image| same_path(&image, path))
}


/// A path selector that is not the exact path of an observed image may not be an OS directory (second net behind `DirectorySelector`).
pub fn directory_reasons(loaded: &LoadedPolicy, images: &[ObservedImage], path: &CanonicalPath) -> Vec<Reason> {
    if is_image_path(images, path) {
        Vec::new()
    } else {
        loaded
            .os_dirs
            .iter()
            .filter(|entry| covers(&entry.path, path))
            .map(|entry| Reason::OsDirectory {
                directory: entry.name.clone(),
            })
            .collect()
    }
}


pub fn path_selector_reasons(loaded: &LoadedPolicy, images: &[ObservedImage], value: &str) -> Vec<Reason> {
    match canonical_path(value) {
        Err(form) => vec![Reason::NonCanonical { form }],
        Ok(path) => [
            location_reasons(loaded, &path),
            directory_reasons(loaded, images, &path),
            file_sensor_reasons(loaded, value),
        ]
        .concat(),
    }
}


pub fn is_bound(exclusion: &Exclusion) -> bool {
    let images = &exclusion.evidence.observed_images;
    let value = &exclusion.selector.value;
    match exclusion.selector.kind {
        SelectorKind::Hash => {
            exclusion
                .evidence
                .known_hash
                .as_ref()
                .is_none_or(|known| known.eq_ignore_ascii_case(value))
                && images.iter().any(|image| image.sha256.eq_ignore_ascii_case(value))
        }
        SelectorKind::Path | SelectorKind::ProcessName => match canonical_path(value) {
            Err(_) => true,
            Ok(path) => is_image_path(images, &path),
        },
        SelectorKind::CommandLine => {
            command_line_paths(value).map_or(true, |paths| paths.first().is_some_and(|executable| is_image_path(images, executable)))
        }
        SelectorKind::Signer => true,
    }
}


/// Every selector must name an observed image; a selector already refused for its form or scope gets no second reason.
pub fn directory_selector_reasons(exclusion: &Exclusion) -> Vec<Reason> {
    let images = &exclusion.evidence.observed_images;
    let is_directory = exclusion.selector.kind == SelectorKind::Path
        && canonical_path(&exclusion.selector.value)
            .is_ok_and(|path| images.iter().filter_map(image_path).any(|image| is_strict_ancestor(&path, &image)));
    is_directory.then_some(Reason::DirectorySelector).into_iter().collect()
}


pub fn binding_reasons(exclusion: &Exclusion) -> Vec<Reason> {
    let applies = !exclusion.evidence.observed_images.is_empty()
        && match exclusion.selector.kind {
            SelectorKind::Hash => valid_hash(&exclusion.selector.value),
            _ => exclusion.scope == Scope::SingleEndpoint,
        };
    let directory = directory_selector_reasons(exclusion);
    let unbound = (applies && directory.is_empty() && !is_bound(exclusion)).then_some(Reason::SelectorNotInEvidence);
    directory.into_iter().chain(unbound).collect()
}


pub fn token_reasons(loaded: &LoadedPolicy, token: &str) -> Vec<Reason> {
    let trimmed = token.trim_matches(|character: char| !character.is_alphanumeric());
    let file_name = trimmed.rsplit(['/', '\\']).find(|part| !part.is_empty()).unwrap_or(trimmed);
    [
        listed_stem(&loaded.interpreter_stems, file_name).map(|listed| Reason::InterpreterInCommandLine { name: listed.clone() }),
        listed_position(&loaded.sensor_stems, file_name).map(|index| Reason::ListedSecuritySensor { index }),
        listed_stem(&loaded.tool_stems, file_name).map(|listed| Reason::ServiceControlInCommandLine { name: listed.clone() }),
    ]
    .into_iter()
    .flatten()
    .collect()
}


pub fn command_words_reasons(loaded: &LoadedPolicy, value: &str) -> Vec<Reason> {
    value
        .split(' ')
        .filter(|token| !token.is_empty())
        .flat_map(|token| token_reasons(loaded, token))
        .collect()
}


/// Every path-like argument after the executable is checked against the OS directories, whatever the images say.
pub fn argument_directory_reasons(loaded: &LoadedPolicy, value: &str) -> Vec<Reason> {
    command_line_paths(value).map_or_else(
        |_| Vec::new(),
        |paths| paths.iter().skip(1).flat_map(|path| directory_reasons(loaded, &[], path)).collect(),
    )
}


pub fn wide_scope_reason(kind: SelectorKind) -> Reason {
    match kind {
        SelectorKind::Path => Reason::PathAtWideScope,
        SelectorKind::ProcessName => Reason::ProcessNameAtWideScope,
        SelectorKind::CommandLine => Reason::CommandLineAtWideScope,
        SelectorKind::Signer | SelectorKind::Hash => Reason::SignerSelector,
    }
}


/// At global or group scope only a hash is allowed; at single endpoint scope a path form is canonical or refused.
pub fn selector_reasons(loaded: &LoadedPolicy, exclusion: &Exclusion) -> Vec<Reason> {
    let Selector { kind, value } = &exclusion.selector;
    let wide = exclusion.scope != Scope::SingleEndpoint;
    match (kind, wide) {
        (SelectorKind::Hash, _) => hash_reasons(exclusion),
        (SelectorKind::Signer, _) => vec![Reason::SignerSelector],
        (_, true) => vec![wide_scope_reason(*kind)],
        (SelectorKind::Path | SelectorKind::ProcessName, false) => path_selector_reasons(loaded, &exclusion.evidence.observed_images, value),
        (SelectorKind::CommandLine, false) => [
            path_reasons(loaded, command_line_paths(value)),
            argument_directory_reasons(loaded, value),
            command_words_reasons(loaded, value),
        ]
        .concat(),
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
        image_reasons(loaded, exclusion),
        binding_reasons(exclusion),
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
