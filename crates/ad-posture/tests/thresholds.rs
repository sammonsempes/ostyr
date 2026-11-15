use ad_posture::error::ThresholdsError;
use ad_posture::thresholds::{
    load_thresholds, DEFAULT_INACTIVE_DAYS, DEFAULT_KRBTGT_MAX_AGE_DAYS, DEFAULT_PRIVILEGED_MAX_MEMBERS, MAX_DAYS, MAX_MEMBERS,
};
use std::error::Error;
use std::path::PathBuf;
use tempfile::TempDir;


const CUSTOM_DAYS: u32 = 30;


const CUSTOM_MEMBERS: usize = 2;


const CUSTOM_INACTIVE: u32 = 45;


fn write_yaml(directory: &TempDir, text: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = directory.path().join("thresholds.yaml");
    std::fs::write(&path, text)?;
    Ok(path)
}


fn refused_field(text: &str) -> Result<&'static str, Box<dyn Error>> {
    let directory = TempDir::new()?;
    match load_thresholds(&write_yaml(&directory, text)?) {
        Err(ThresholdsError::Range { field, .. }) => Ok(field),
        other => Err(format!("expected a range error, got {other:?}").into()),
    }
}


#[test]
fn an_empty_document_gives_the_defaults() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let thresholds = load_thresholds(&write_yaml(&directory, "{}\n")?)?;
    assert_eq!(thresholds.krbtgt_max_age_days, DEFAULT_KRBTGT_MAX_AGE_DAYS);
    assert_eq!(thresholds.privileged_max_members, DEFAULT_PRIVILEGED_MAX_MEMBERS);
    assert_eq!(thresholds.inactive_days, DEFAULT_INACTIVE_DAYS);
    Ok(())
}


#[test]
fn every_key_can_be_set() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let text = format!("krbtgt_max_age_days: {CUSTOM_DAYS}\nprivileged_max_members: {CUSTOM_MEMBERS}\ninactive_days: {CUSTOM_INACTIVE}\n");
    let thresholds = load_thresholds(&write_yaml(&directory, &text)?)?;
    assert_eq!(thresholds.krbtgt_max_age_days, CUSTOM_DAYS);
    assert_eq!(thresholds.privileged_max_members, CUSTOM_MEMBERS);
    assert_eq!(thresholds.inactive_days, CUSTOM_INACTIVE);
    Ok(())
}


#[test]
fn an_unknown_key_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let error = load_thresholds(&write_yaml(&directory, "krbtgt_days: 3\n")?).err().ok_or("accepted")?;
    assert!(matches!(error, ThresholdsError::Config(_)));
    assert!(!error.to_string().is_empty());
    Ok(())
}


#[test]
fn a_missing_file_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let error = load_thresholds(&directory.path().join("absent.yaml")).err().ok_or("accepted")?;
    assert!(matches!(error, ThresholdsError::Config(_)));
    Ok(())
}


#[test]
fn each_key_is_range_checked() -> Result<(), Box<dyn Error>> {
    assert_eq!(refused_field("krbtgt_max_age_days: 0\n")?, "krbtgt_max_age_days");
    assert_eq!(refused_field(&format!("krbtgt_max_age_days: {}\n", MAX_DAYS + 1))?, "krbtgt_max_age_days");
    assert_eq!(refused_field("privileged_max_members: 0\n")?, "privileged_max_members");
    assert_eq!(
        refused_field(&format!("privileged_max_members: {}\n", MAX_MEMBERS + 1))?,
        "privileged_max_members"
    );
    assert_eq!(refused_field("inactive_days: 0\n")?, "inactive_days");
    assert_eq!(refused_field(&format!("inactive_days: {}\n", MAX_DAYS + 1))?, "inactive_days");
    Ok(())
}
