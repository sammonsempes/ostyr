use crate::error::ActionError;
use crate::model::{Action, PackageSelection, MAX_PACKAGES, MAX_PACKAGE_NAME_LENGTH, PACKAGE_NAME_PUNCTUATION};


/// One grammar for signing and verification: letters, digits and `.+-_:~`, no leading dash, bounded length.
pub fn validate_package_name(name: &str) -> Result<(), ActionError> {
    if name.is_empty() {
        Err(ActionError::EmptyPackageName)
    } else if name.len() > MAX_PACKAGE_NAME_LENGTH {
        Err(ActionError::PackageNameTooLong)
    } else if name.starts_with('-') {
        Err(ActionError::PackageNameLeadingDash)
    } else if name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || PACKAGE_NAME_PUNCTUATION.contains(character))
    {
        Ok(())
    } else {
        Err(ActionError::PackageNameCharacter)
    }
}


pub fn validate_selection(selection: &PackageSelection) -> Result<(), ActionError> {
    match selection {
        PackageSelection::AllAllowed => Ok(()),
        PackageSelection::Named(names) if names.is_empty() => Err(ActionError::NoPackages),
        PackageSelection::Named(names) if names.len() > MAX_PACKAGES => Err(ActionError::TooManyPackages),
        PackageSelection::Named(names) => names.iter().try_for_each(|name| validate_package_name(name)),
    }
}


pub fn validate_action(action: &Action) -> Result<(), ActionError> {
    match action {
        Action::InstallUpdates { packages, .. } => validate_selection(packages),
        _ => Ok(()),
    }
}
