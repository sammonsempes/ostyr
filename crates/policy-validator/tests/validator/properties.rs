use crate::support::{exclusion, hash, image, loaded, probe, reasons_for};
use policy_validator::model::{Decision, Proposal, Reason, Scope, SelectorKind};
use policy_validator::path::canonical_path;
use policy_validator::policy::DEFAULT_INTERPRETERS;
use policy_validator::rules::{validate, wide_scope_reason};
use proptest::prelude::*;


fn failed(error: Box<dyn std::error::Error>) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}


fn wide_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![Just(Scope::Global), Just(Scope::EndpointGroup)]
}


fn non_hash_kind() -> impl Strategy<Value = SelectorKind> {
    prop_oneof![
        Just(SelectorKind::Path),
        Just(SelectorKind::ProcessName),
        Just(SelectorKind::CommandLine),
        Just(SelectorKind::Signer)
    ]
}


const DRIVE_PREFIX_LENGTH: usize = 2;


fn any_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![Just(Scope::Global), Just(Scope::EndpointGroup), Just(Scope::SingleEndpoint)]
}


fn any_kind() -> impl Strategy<Value = SelectorKind> {
    prop_oneof![Just(SelectorKind::Hash), non_hash_kind()]
}


proptest! {
    #[test]
    fn at_global_or_group_scope_a_non_hash_selector_is_always_refused(scope in wide_scope(), kind in non_hash_kind(), value in ".{0,80}") {
        let found = probe(scope, kind, &value).map_err(failed)?;
        prop_assert!(found.contains(&wide_scope_reason(kind)));
    }

    #[test]
    fn any_proposal_gives_a_consistent_verdict_without_panicking(scope in any_scope(), kind in any_kind(), value in "[ -~\\n\\t]{0,80}") {
        let policy = loaded().map_err(failed)?;
        let verdict = validate(&policy, &Proposal::Exclusion(exclusion(scope, kind, &value)));
        prop_assert_eq!(verdict.decision == Decision::Accepted, verdict.reasons.is_empty());
    }

    #[test]
    fn a_global_hash_of_a_configured_interpreter_is_always_refused(
        index in 0..DEFAULT_INTERPRETERS.len(),
        upper in any::<bool>(),
        digits in "[0-9]{0,3}",
        directory in prop_oneof![Just(""), Just("/usr/bin/"), Just("C:\\Windows\\System32\\")],
    ) {
        let configured = DEFAULT_INTERPRETERS.get(index).copied().unwrap_or("sh");
        let (stem, extension) = configured.split_once('.').unwrap_or((configured, ""));
        let plain = format!("{directory}{stem}{digits}{}{extension}", if extension.is_empty() { "" } else { "." });
        let name = if upper { plain.to_uppercase() } else { plain };
        let mut proposal = exclusion(Scope::Global, SelectorKind::Hash, &hash());
        proposal.evidence.observed_images = vec![image(&name)];
        let found = reasons_for(proposal).map_err(failed)?;
        prop_assert_eq!(found, vec![Reason::SystemBinary { name }]);
    }

    #[test]
    fn an_accepted_path_has_no_wildcard_variable_or_dot_segment(value in "[a-zA-Z0-9/\\\\:.*?%~ $-]{0,40}") {
        let found = probe(Scope::SingleEndpoint, SelectorKind::Path, &value).map_err(failed)?;
        let clean = found.iter().all(|reason| !matches!(reason, Reason::NonCanonical { .. }));
        prop_assert_eq!(clean, canonical_path(&value).is_ok());
        if clean {
            prop_assert!(!value.contains(['*', '?', '%', '$']));
            prop_assert!(!value.chars().skip(DRIVE_PREFIX_LENGTH).any(|character| character == ':'));
            prop_assert!(!value.split(['/', '\\']).any(|part| part == "." || part == ".."));
        }
    }
}
