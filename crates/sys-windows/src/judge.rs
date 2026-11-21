use crate::descriptor::{ACE_ALLOWED, ACE_ALLOWED_CALLBACK, ACE_ALLOWED_CALLBACK_OBJECT, ACE_ALLOWED_OBJECT};
use crate::descriptor::{ACE_DENIED, ACE_DENIED_CALLBACK, ACE_DENIED_CALLBACK_OBJECT, ACE_DENIED_OBJECT};
use crate::types::{Ace, DirAclError, ParsedDescriptor, Principals};
use std::path::Path;


pub const SID_SYSTEM: &str = "S-1-5-18";


pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";


pub const SID_CREATOR_OWNER: &str = "S-1-3-0";


pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";


pub const SERVICE_SID_PREFIX: &str = "S-1-5-80-";


const SID_PREFIX: &str = "S-1-";


pub const GENERIC_READ: u32 = 0x8000_0000;


pub const GENERIC_WRITE: u32 = 0x4000_0000;


pub const GENERIC_EXECUTE: u32 = 0x2000_0000;


pub const GENERIC_ALL: u32 = 0x1000_0000;


pub const FILE_GENERIC_READ: u32 = 0x0012_0089;


pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;


pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;


pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;


pub const READ_ONLY_RIGHTS: u32 = 0x0012_00A9;


/// The principals every directory may grant rights to, plus the process's own account when it is SYSTEM or a service SID.
pub fn principals_from_token_user(user_sid: &str) -> Result<Principals, DirAclError> {
    let base = [SID_SYSTEM, SID_ADMINISTRATORS, SID_CREATOR_OWNER, SID_OWNER_RIGHTS];
    let valid = user_sid.starts_with(SID_PREFIX);
    let agent_account = user_sid == SID_SYSTEM || user_sid.starts_with(SERVICE_SID_PREFIX);
    let mut trusted: Vec<String> = base.iter().map(|sid| (*sid).to_string()).collect();
    valid.then_some(()).ok_or(DirAclError::InvalidSid("token user is not a SID string"))?;
    if agent_account {
        trusted.push(user_sid.to_string());
    }
    Ok(Principals { trusted })
}


/// The mask with each generic right replaced by the file rights it stands for; other bits are kept as they are.
pub fn map_generic(mask: u32) -> u32 {
    let generic = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (GENERIC_ALL, FILE_ALL_ACCESS),
    ]
    .iter()
    .filter(|(bit, _)| mask & bit != 0)
    .fold(mask & !generic, |mapped, (_, rights)| mapped | rights)
}


/// The bits an allow entry grants beyond the read-only set, after generic mapping.
pub fn refused_bits(mask: u32) -> u32 {
    map_generic(mask) & !READ_ONLY_RIGHTS
}


fn judge_ace(path: &Path, principals: &Principals, ace: &Ace) -> Result<(), DirAclError> {
    let allow = [ACE_ALLOWED, ACE_ALLOWED_OBJECT, ACE_ALLOWED_CALLBACK, ACE_ALLOWED_CALLBACK_OBJECT];
    let deny = [ACE_DENIED, ACE_DENIED_OBJECT, ACE_DENIED_CALLBACK, ACE_DENIED_CALLBACK_OBJECT];
    let trusted = principals.trusted.contains(&ace.sid);
    let bits = refused_bits(ace.mask);
    if deny.contains(&ace.kind) {
        Ok(())
    } else if !allow.contains(&ace.kind) {
        Err(DirAclError::UnknownAceType {
            path: path.to_path_buf(),
            kind: ace.kind,
        })
    } else if trusted || bits == 0 {
        Ok(())
    } else {
        Err(DirAclError::UntrustedAce {
            path: path.to_path_buf(),
            sid: ace.sid.clone(),
            bits,
        })
    }
}


/// Judges a spool directory: a DACL that is not NULL, no allow entry for an untrusted SID beyond read rights, then a trusted owner.
pub fn judge_spool_dir(path: &Path, descriptor: &ParsedDescriptor, principals: &Principals) -> Result<(), DirAclError> {
    let aces = descriptor
        .dacl
        .as_ref()
        .ok_or_else(|| DirAclError::NullDacl { path: path.to_path_buf() })?;
    aces.iter().try_for_each(|ace| judge_ace(path, principals, ace))?;
    principals
        .trusted
        .contains(&descriptor.owner)
        .then_some(())
        .ok_or_else(|| DirAclError::UntrustedOwner {
            path: path.to_path_buf(),
            sid: descriptor.owner.clone(),
        })
}
