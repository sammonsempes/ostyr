use core_config::secret::{PlaintextSecret, SecretRef, SECRET_PREFIXES};
use std::error::Error;


type TestResult = Result<(), Box<dyn Error>>;


#[test]
fn references_are_accepted() -> TestResult {
    assert!(SecretRef::try_from("vault://kv/a".to_string()).is_ok());
    assert!(SecretRef::try_from("openbao://kv/a".to_string()).is_ok());
    assert!(SecretRef::try_from("sops:secrets/a.enc.yaml".to_string()).is_ok());
    Ok(())
}


#[test]
fn values_and_empty_references_are_rejected() -> TestResult {
    let samples = ["hunter2", "", "vault://", "sops:", "https://vault://x", " vault://kv"];
    assert!(samples.iter().all(|sample| SecretRef::try_from((*sample).to_string()).is_err()));
    assert_eq!(SECRET_PREFIXES.len(), 3);
    Ok(())
}


#[test]
fn rejection_message_has_no_value() -> TestResult {
    assert!(PlaintextSecret.to_string().contains("never a value"));
    Ok(())
}
