use crate::descriptor::{ACE_ALLOWED, ACE_ALLOWED_CALLBACK, ACE_ALLOWED_CALLBACK_OBJECT, ACE_ALLOWED_OBJECT};
use crate::descriptor::{ACE_DENIED, ACE_DENIED_CALLBACK, ACE_DENIED_CALLBACK_OBJECT, ACE_DENIED_OBJECT};
use crate::judge::map_generic;
use crate::types::{DirAclError, ParsedDescriptor, Principals, VolumePath};
use std::path::Path;


pub const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";


pub const INHERIT_ONLY: u8 = 0x08;


pub const DELETE: u32 = 0x0001_0000;


pub const FILE_DELETE_CHILD: u32 = 0x0040;


pub const WRITE_DAC: u32 = 0x0004_0000;


pub const WRITE_OWNER: u32 = 0x0008_0000;


pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;


pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;


pub const ANCESTOR_FORBIDDEN_RIGHTS: u32 = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY | MAXIMUM_ALLOWED;


const DRIVE_PREFIX_CHARS: usize = 3;


const FORBIDDEN_NAME_CHARS: &str = ":<>\"|?*";


fn is_separator(character: char) -> bool {
    character == '\\' || character == '/'
}


fn component_fault(component: &str) -> Option<&'static str> {
    if component.is_empty() {
        Some("empty component")
    } else if component == "." || component == ".." {
        Some("dot component")
    } else if component
        .chars()
        .any(|character| character.is_control() || FORBIDDEN_NAME_CHARS.contains(character))
    {
        Some("forbidden character in a component")
    } else if component.ends_with('.') || component.ends_with(' ') {
        Some("component ends with a dot or a space")
    } else {
        None
    }
}


/// Splits `X:\dir\sub` into its root and components; relative, UNC, `\\?\`, `\\.\`, dot, stream and empty components are refused by name.
pub fn split_volume_path(text: &str) -> Result<VolumePath, DirAclError> {
    let bad = |reason: &'static str| DirAclError::BadPath {
        path: text.to_string(),
        reason,
    };
    let mut characters = text.chars();
    let letter = characters
        .next()
        .filter(char::is_ascii_alphabetic)
        .ok_or_else(|| bad("no drive letter"))?;
    characters
        .next()
        .filter(|character| *character == ':')
        .ok_or_else(|| bad("no drive letter"))?;
    characters
        .next()
        .filter(|character| is_separator(*character))
        .ok_or_else(|| bad("not rooted at the volume"))?;
    let rest = text.chars().skip(DRIVE_PREFIX_CHARS).collect::<String>();
    let trimmed = rest.strip_suffix(is_separator).unwrap_or(&rest);
    let components: Vec<String> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split(is_separator).map(str::to_string).collect()
    };
    components
        .iter()
        .find_map(|component| component_fault(component))
        .map_or(Ok(()), |reason| Err(bad(reason)))?;
    Ok(VolumePath {
        root: format!("{}:\\", letter.to_ascii_uppercase()),
        components,
    })
}


/// The root and then each cumulative prefix down to the full path: the directories the walk opens, in order.
pub fn walk_prefixes(path: &VolumePath) -> Vec<String> {
    let first = path.root.clone();
    let rest = path
        .components
        .iter()
        .scan(first.trim_end_matches('\\').to_string(), |current, component| {
            current.push('\\');
            current.push_str(component);
            Some(current.clone())
        });
    std::iter::once(first).chain(rest).collect()
}


/// The principals an ancestor directory may belong to or grant rights to: the spool principals plus `NT SERVICE\TrustedInstaller`.
pub fn ancestor_principals(principals: &Principals) -> Principals {
    let mut trusted = principals.trusted.clone();
    trusted.push(SID_TRUSTED_INSTALLER.to_string());
    Principals { trusted }
}


/// Judges one ancestor of the spool directory: a trusted owner and no effective allow entry that lets an untrusted SID delete, re-ACL or take it.
pub fn judge_ancestor(path: &Path, descriptor: &ParsedDescriptor, principals: &Principals) -> Result<(), DirAclError> {
    let allow = [ACE_ALLOWED, ACE_ALLOWED_OBJECT, ACE_ALLOWED_CALLBACK, ACE_ALLOWED_CALLBACK_OBJECT];
    let deny = [ACE_DENIED, ACE_DENIED_OBJECT, ACE_DENIED_CALLBACK, ACE_DENIED_CALLBACK_OBJECT];
    let trusted = ancestor_principals(principals);
    let aces = descriptor
        .dacl
        .as_ref()
        .ok_or_else(|| DirAclError::NullDacl { path: path.to_path_buf() })?;
    aces.iter().try_for_each(|ace| {
        let bits = map_generic(ace.mask) & ANCESTOR_FORBIDDEN_RIGHTS;
        if deny.contains(&ace.kind) || ace.flags & INHERIT_ONLY != 0 {
            Ok(())
        } else if !allow.contains(&ace.kind) {
            Err(DirAclError::UnknownAceType {
                path: path.to_path_buf(),
                kind: ace.kind,
            })
        } else if bits == 0 || trusted.trusted.contains(&ace.sid) {
            Ok(())
        } else {
            Err(DirAclError::UntrustedAce {
                path: path.to_path_buf(),
                sid: ace.sid.clone(),
                bits,
            })
        }
    })?;
    trusted
        .trusted
        .contains(&descriptor.owner)
        .then_some(())
        .ok_or_else(|| DirAclError::UntrustedOwner {
            path: path.to_path_buf(),
            sid: descriptor.owner.clone(),
        })
}
