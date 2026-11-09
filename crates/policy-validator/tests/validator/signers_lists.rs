use crate::support::{bench, hash, loaded, probe, replace_file};
use crate::types::TestResult;
use core_config::reload::{reload, ReloadOutcome};
use policy_validator::model::{Reason, Scope, SelectorKind};
use policy_validator::policy::Policy;
use policy_validator::reload::{list_summary, policy_state};
use policy_validator::rules::{listed_stem, wide_scope_reason};


#[test]
fn a_signer_selector_is_refused_at_every_scope() -> TestResult {
    for scope in [Scope::Global, Scope::EndpointGroup, Scope::SingleEndpoint] {
        for signer in ["Vendor Ltd", "Microsoft Corporation", ""] {
            assert!(
                probe(scope, SelectorKind::Signer, signer)?.contains(&Reason::SignerSelector),
                "{scope:?} {signer}"
            );
        }
    }
    assert_eq!(wide_scope_reason(SelectorKind::Signer), Reason::SignerSelector);
    Ok(())
}


#[test]
fn a_path_like_argument_is_checked_against_os_directories_and_interpreters() -> TestResult {
    let found = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool /usr/bin/python3-dbg")?;
    assert!(
        found.contains(&Reason::OsDirectory {
            directory: "/usr".to_owned()
        }),
        "{found:?}"
    );
    assert!(
        found.contains(&Reason::InterpreterInCommandLine { name: "python3".to_owned() }),
        "{found:?}"
    );
    let plain = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool /srv/data")?;
    assert_eq!(plain, vec![]);
    Ok(())
}


#[test]
fn an_env_bash_static_command_line_is_refused() -> TestResult {
    let found = probe(Scope::SingleEndpoint, SelectorKind::CommandLine, "/srv/app/bin/tool bash-static")?;
    assert!(found.contains(&Reason::InterpreterInCommandLine { name: "bash".to_owned() }), "{found:?}");
    Ok(())
}


#[test]
fn a_stem_matches_with_a_dash_suffix_or_digits_only() -> TestResult {
    let stems = vec!["python3".to_owned()];
    assert!(listed_stem(&stems, "python3-dbg").is_some());
    assert!(listed_stem(&stems, "python3.11").is_some());
    assert!(listed_stem(&stems, "python311").is_some());
    assert!(listed_stem(&stems, "python3x").is_none());
    for separated in ["python3_static", "python3+static"] {
        assert!(listed_stem(&stems, separated).is_some(), "{separated}");
    }
    Ok(())
}


#[test]
fn run_shm_is_a_writable_prefix() -> TestResult {
    assert!(Policy::default().user_writable_prefixes.contains(&"/run/shm".to_owned()));
    assert!(loaded()?.writable.iter().any(|entry| entry.name == "/run/shm"));
    assert!(
        probe(Scope::SingleEndpoint, SelectorKind::Path, "/run/shm/x")?.contains(&Reason::UserWritableDirectory {
            directory: "/run/shm".to_owned()
        })
    );
    assert!(probe(Scope::Global, SelectorKind::Hash, &hash())?.is_empty());
    Ok(())
}


#[test]
fn the_reload_diff_covers_the_lists_without_their_entries() -> TestResult {
    let state = policy_state(&loaded()?);
    for key in ["os_directories", "service_tools", "os_vendor_signers"] {
        let value = state.get(key).ok_or(key)?;
        assert!(value.starts_with("count="), "{key}: {value}");
        assert!(value.contains(" sha256-salted="), "{key}: {value}");
    }
    assert!(!state.get("os_vendor_signers").ok_or("missing")?.contains("canonical"));
    assert_ne!(list_summary(&["a".to_owned()]), list_summary(&["b".to_owned()]));
    let bench = bench("{}")?;
    replace_file(&bench.policy_file, "security_sensors: []\n")?;
    let outcome = reload(&bench.engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Applied { keys } if keys.contains(&"security_sensors".to_owned())),
        "{outcome:?}"
    );
    Ok(())
}
