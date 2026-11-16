use crate::error::{PolicyError, ValidationError};
use crate::extension_grammar::{is_chromium_id, is_firefox_id, is_update_url};
use crate::limits::{MAX_EXTENSIONS, MAX_POLICY_BYTES};
use crate::model::{Action, Mode, Owner, Reason};
use core_config::parse::{parse_document, read_text_capped};
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::collections::HashSet;
use std::io::Read;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Chromium,
    Firefox,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionAction {
    Allow,
    Block,
    Force,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawExtension {
    pub browser: Browser,
    pub id: String,
    pub action: ExtensionAction,
    pub update_url: Option<String>,
    pub owner: Owner,
    pub reason: Reason,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawExtension")]
pub struct Extension {
    pub browser: Browser,
    pub id: String,
    pub action: ExtensionAction,
    pub update_url: Option<String>,
    pub owner: Owner,
    pub reason: Reason,
}


impl TryFrom<RawExtension> for Extension {
    type Error = ValidationError;

    fn try_from(raw: RawExtension) -> Result<Self, Self::Error> {
        let id_ok = match raw.browser {
            Browser::Chromium => is_chromium_id(&raw.id),
            Browser::Firefox => is_firefox_id(&raw.id),
        };
        let url_ok = raw.update_url.as_deref().is_none_or(is_update_url);
        if !id_ok {
            Err(match raw.browser {
                Browser::Chromium => ValidationError::ChromiumId,
                Browser::Firefox => ValidationError::FirefoxId,
            })
        } else if !url_ok {
            Err(ValidationError::UpdateUrl)
        } else {
            Ok(Self {
                browser: raw.browser,
                id: raw.id,
                action: raw.action,
                update_url: raw.update_url,
                owner: raw.owner,
                reason: raw.reason,
            })
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPolicy {
    #[serde(default)]
    pub mode: Mode,
    pub default: Action,
    #[serde(default)]
    pub extensions: Vec<Extension>,
}


#[derive(Debug, Deserialize)]
pub struct ExtensionCount {
    #[serde(default)]
    pub extensions: Vec<IgnoredAny>,
}


/// A `force` entry needs its URL and no other action has one.
pub fn url_problem(extension: &Extension) -> Option<ValidationError> {
    match (extension.action, extension.update_url.is_some()) {
        (ExtensionAction::Force, false) => Some(ValidationError::UpdateUrlRequired),
        (ExtensionAction::Allow | ExtensionAction::Block, true) => Some(ValidationError::UpdateUrlForbidden),
        _ => None,
    }
}


/// The first entry with a problem and its list index; Firefox ids are compared case-insensitively, as are Chromium ids (already lowercase).
pub fn first_problem(extensions: &[Extension]) -> Option<(usize, ValidationError)> {
    let mut seen = HashSet::new();
    extensions.iter().enumerate().find_map(|(index, extension)| {
        let fresh = seen.insert((extension.browser, extension.id.to_ascii_lowercase()));
        if fresh {
            url_problem(extension).map(|problem| (index, problem))
        } else {
            Some((index, ValidationError::DuplicateExtension))
        }
    })
}


/// Reads at most `MAX_POLICY_BYTES`, parses strictly, refuses more than `MAX_EXTENSIONS` entries, a duplicate or a bad `update_url` by index.
pub fn parse_extension_policy(reader: &mut dyn Read, file: &str) -> Result<ExtensionPolicy, PolicyError> {
    let text = read_text_capped(reader, file, MAX_POLICY_BYTES)?;
    let counted: ExtensionCount = parse_document(&text, file)?;
    let count = counted.extensions.len();
    if count > MAX_EXTENSIONS {
        Err(PolicyError::TooManyExtensions {
            file: file.to_string(),
            count,
        })
    } else {
        let policy: ExtensionPolicy = parse_document(&text, file)?;
        first_problem(&policy.extensions).map_or(Ok(policy), |(index, source)| {
            Err(PolicyError::Extension {
                file: file.to_string(),
                index,
                source,
            })
        })
    }
}
