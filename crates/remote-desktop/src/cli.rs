use crate::error::{CliError, TokenError};
use crate::model::{IssueRequest, Line, RelayClaims, Verifier, GROUP_OTHER_MASK, MAX_SEED_FILE_BYTES, MAX_TOKEN_BYTES};
use crate::sign::{memory_signer, new_identifiers};
use crate::token::{issue_token, verify_token};
use crate::types::FillFn;
use core_pg::password::{open_regular, read_secret};
use data_encoding::HEXLOWER;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use std::fs::Metadata;
use std::io::{self, BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;


pub const ISSUE_USAGE: &str = "issue <seed-file> <claims-json>";


/// A token, a carriage return and a line feed, plus one byte to tell an oversize line from a full one.
pub const LINE_LIMIT: usize = MAX_TOKEN_BYTES + 3;


/// Writes `seed <hex>` and `public <hex>` for a fresh random key.
pub fn write_keypair<Output: Write>(fill: FillFn, out: &mut Output) -> Result<(), CliError> {
    let mut seed = Zeroizing::new([0; SECRET_KEY_LENGTH]);
    fill(&mut *seed)?;
    let public = SigningKey::from_bytes(&seed).verifying_key();
    writeln!(out, "seed {}", HEXLOWER.encode(seed.as_slice()))?;
    writeln!(out, "public {}", HEXLOWER.encode(&public.to_bytes()))?;
    Ok(())
}


pub fn signing_key_from(seed_hex: &str) -> Result<SigningKey, CliError> {
    let input = seed_hex.as_bytes();
    let mut decoded = Zeroizing::new(vec![0; HEXLOWER.decode_len(input.len())?]);
    HEXLOWER.decode_mut(input, &mut decoded).map_err(|partial| partial.error)?;
    let seed = Zeroizing::new(<[u8; SECRET_KEY_LENGTH]>::try_from(decoded.as_slice()).map_err(|_| CliError::Seed)?);
    Ok(SigningKey::from_bytes(&seed))
}


/// Mode bits and owner of the opened handle, with the effective user of the process.
#[cfg(unix)]
pub fn mode_and_owners(metadata: &Metadata) -> Result<(u32, u32, u32), CliError> {
    Ok((metadata.mode(), metadata.uid(), rustix::process::geteuid().as_raw()))
}


#[cfg(not(unix))]
pub fn mode_and_owners(_metadata: &Metadata) -> Result<(u32, u32, u32), CliError> {
    Err(CliError::Unsupported)
}


/// The seed file must grant nothing to group or other and belong to the process user.
pub fn check_owner_and_mode(mode: u32, owner: u32, process_user: u32) -> Result<(), CliError> {
    if mode & GROUP_OTHER_MASK != 0 {
        Err(CliError::SeedMode)
    } else if owner != process_user {
        Err(CliError::SeedOwner)
    } else {
        Ok(())
    }
}


/// Opened without blocking, regular file, mode and owner judged on the opened handle, bounded read, then the hex seed.
pub fn read_signing_key(path: &Path) -> Result<SigningKey, CliError> {
    let mut handle = open_regular(path).map_err(|_| CliError::SeedFile)?;
    let metadata = handle.metadata().map_err(CliError::Inspect)?;
    let (mode, owner, process_user) = mode_and_owners(&metadata)?;
    check_owner_and_mode(mode, owner, process_user)?;
    let bytes = read_secret(&mut handle, MAX_SEED_FILE_BYTES, "").map_err(|_| CliError::SeedFile)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| CliError::SeedText)?;
    signing_key_from(text.trim())
}


/// Writes the token as one line; the session id and the nonce are random, the token starts now.
pub fn write_issued<Output: Write>(args: &[&str], now: u64, fill: FillFn, out: &mut Output) -> Result<(), CliError> {
    match args {
        [seed_file, claims_json] => {
            let request: IssueRequest = serde_json::from_str(claims_json)?;
            let (session_id, nonce) = new_identifiers(fill)?;
            let claims = RelayClaims {
                key_id: request.key_id,
                tenant: request.tenant,
                session_id,
                device_peer_id: request.device_peer_id,
                viewer_subject: request.viewer_subject,
                not_before: now,
                expires_at: now.saturating_add(request.lifetime_seconds),
                nonce,
            };
            let token = issue_token(&memory_signer(read_signing_key(Path::new(seed_file))?), &claims)?;
            writeln!(out, "{token}")?;
            Ok(())
        }
        _ => Err(CliError::Usage(ISSUE_USAGE)),
    }
}


/// Reads at most `LINE_LIMIT` bytes of one line and skips the rest of an oversize one without buffering it.
pub fn read_line<Input: BufRead>(input: &mut Input) -> io::Result<Option<Line>> {
    let mut buffer = Vec::new();
    let read = input.by_ref().take(LINE_LIMIT as u64).read_until(b'\n', &mut buffer)?;
    if read == 0 {
        Ok(None)
    } else if buffer.ends_with(b"\n") || read < LINE_LIMIT {
        Ok(Some(Line::Text(buffer)))
    } else {
        input.skip_until(b'\n')?;
        Ok(Some(Line::TooLong))
    }
}


pub fn line_verdict(verifier: &Verifier, line: &Line, expected_peer: &str, expected_tenant: &str, now: u64) -> String {
    match line {
        Line::TooLong => format!("refused {}", TokenError::TooLarge),
        Line::Text(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => match verify_token(verifier, text.trim(), expected_peer, expected_tenant, now) {
                Ok(claims) => format!("accepted {}", HEXLOWER.encode(&claims.session_id)),
                Err(refusal) => format!("refused {refusal}"),
            },
            Err(_) => "refused token is not text".to_owned(),
        },
    }
}


/// One token per line in; `accepted <session>` or `refused <reason>` per line out, flushed so a peer can read it live.
pub fn verify_session<Input: BufRead, Output: Write>(
    verifier: &Verifier,
    mut input: Input,
    out: &mut Output,
    clock: fn() -> u64,
    expected_peer: &str,
    expected_tenant: &str,
) -> Result<(), CliError> {
    std::iter::from_fn(|| read_line(&mut input).transpose()).try_for_each(|line| {
        let verdict = line_verdict(verifier, &line?, expected_peer, expected_tenant, clock());
        writeln!(out, "{verdict}")?;
        Ok(out.flush()?)
    })
}
