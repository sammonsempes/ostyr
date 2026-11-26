#![cfg(windows)]
use crate::pe_version::MAX_FILE_BYTES;
use crate::signer::{finish, read_bounded, run_with_deadline, trust_status, CHAIN_REVOCATION_STATUS_UNKNOWN, MICROSOFT_ROOTS};
use crate::types::{SignatureError, SignatureOutcome, SignerChain};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::Duration;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::CERT_CONTEXT;
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, CRYPT_PROVIDER_CERT, CRYPT_PROVIDER_SGNR,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};


const SHARE_READ_ONLY: u32 = 0x1;


const MAX_CERTIFICATE_BYTES: u32 = 0x1_0000;


const PRIMARY_SIGNER: u32 = 0;


struct VerifyState {
    data: Box<WINTRUST_DATA>,
    _file_info: Box<WINTRUST_FILE_INFO>,
}


impl Drop for VerifyState {
    fn drop(&mut self) {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        let data_pointer: *mut WINTRUST_DATA = &mut *self.data;
        // SAFETY: the state opened by the VERIFY call is released with the same data block, which is alive here; the boxed file info it points at lives as long as `self`.
        let status = unsafe { WinVerifyTrust(HWND(INVALID_HANDLE_VALUE.0), &mut action, data_pointer.cast::<c_void>()) };
        tracing::debug!(status, "authenticode state closed");
    }
}


fn deref_copy<Item: Copy>(pointer: *const Item) -> Option<Item> {
    // SAFETY: the pointer comes from the WinTrust state, which stays allocated until the guard closes it after this read; `as_ref` maps null to `None`.
    unsafe { pointer.as_ref() }.copied()
}


fn certificate_der(entry: &CRYPT_PROVIDER_CERT) -> Option<Vec<u8>> {
    let context: CERT_CONTEXT = deref_copy(entry.pCert)?;
    (context.cbCertEncoded <= MAX_CERTIFICATE_BYTES).then_some(())?;
    let length = usize::try_from(context.cbCertEncoded).ok()?;
    (!context.pbCertEncoded.is_null()).then_some(())?;
    // SAFETY: the encoded certificate is `cbCertEncoded` readable bytes owned by the state; it is copied before the state closes.
    let bytes = unsafe { std::slice::from_raw_parts(context.pbCertEncoded.cast_const(), length) };
    Some(bytes.to_vec())
}


fn chain_element(signer: &CRYPT_PROVIDER_SGNR, index: u32) -> Option<CRYPT_PROVIDER_CERT> {
    (index < signer.csCertChain).then_some(())?;
    let offset = usize::try_from(index).ok()?;
    deref_copy(signer.pasCertChain.wrapping_add(offset).cast_const())
}


fn chain_error_status(signer: &CRYPT_PROVIDER_SGNR) -> u32 {
    // SAFETY: `pChainContext` is owned by the open WinTrust state and read before the guard closes it; `as_ref` maps null to `None`, which is judged as an unknown revocation status.
    let status = unsafe { signer.pChainContext.as_ref() }.map(|context| context.TrustStatus.dwErrorStatus);
    status.unwrap_or(CHAIN_REVOCATION_STATUS_UNKNOWN)
}


fn primary_chain(state: HANDLE) -> Option<SignerChain> {
    // SAFETY: the handle is the state data of a VERIFY call that is still open.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    (!provider.is_null()).then_some(())?;
    // SAFETY: `provider` is the provider data of the open state; signer 0 of the primary chain is requested, never a countersigner.
    let signer_pointer = unsafe { WTHelperGetProvSignerFromChain(provider, PRIMARY_SIGNER, false, 0) };
    let signer = deref_copy(signer_pointer.cast_const())?;
    let leaf = certificate_der(&chain_element(&signer, 0)?)?;
    let root = certificate_der(&chain_element(&signer, signer.csCertChain.checked_sub(1)?)?)?;
    Some(SignerChain {
        leaf_der: leaf,
        root_der: root,
        error_status: chain_error_status(&signer),
    })
}


fn wintrust(file: &File) -> Result<(u32, Option<SignerChain>), SignatureError> {
    let mut file_info = Box::new(WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_FILE_INFO>()).map_err(|_| SignatureError::WorkerFailed)?,
        pcwszFilePath: PCWSTR::null(),
        hFile: HANDLE(file.as_raw_handle()),
        pgKnownSubject: std::ptr::null_mut(),
    });
    let mut data = Box::new(WINTRUST_DATA {
        cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_DATA>()).map_err(|_| SignatureError::WorkerFailed)?,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut *file_info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pwszURLReference: PWSTR::null(),
        ..WINTRUST_DATA::default()
    });
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let data_pointer: *mut WINTRUST_DATA = &mut *data;
    let state = VerifyState { data, _file_info: file_info };
    // SAFETY: `data_pointer` points at the boxed block owned by `state`, whose union points at the boxed file info; both outlive the call and the close in `Drop`.
    let code = unsafe { WinVerifyTrust(HWND(INVALID_HANDLE_VALUE.0), &mut action, data_pointer.cast::<c_void>()) }.cast_unsigned();
    let readable = trust_status_has_chain(code);
    let chain = if readable { primary_chain(state.data.hWVTStateData) } else { None };
    Ok((code, chain))
}


fn trust_status_has_chain(code: u32) -> bool {
    matches!(
        trust_status(code),
        crate::types::TrustStatus::Valid | crate::types::TrustStatus::RevocationUnknown
    )
}


/// Opens `path` for reading with a share mode that denies every writer and deleter until the handle closes: a changed file is a refused open, never other bytes.
pub fn open_for_verification(path: &Path) -> Result<File, SignatureError> {
    OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_ONLY)
        .open(path)
        .map_err(|error| SignatureError::Read { kind: error.kind() })
}


fn read_whole(file: &File) -> Result<Vec<u8>, SignatureError> {
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| SignatureError::Read { kind: error.kind() })?;
    let bytes = read_bounded(&mut reader, MAX_FILE_BYTES)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| SignatureError::Read { kind: error.kind() })?;
    Ok(bytes)
}


/// Judges the open file: embedded Authenticode signature, primary signer chain ending in a pinned Microsoft root, leaf subject and code signing, and the PE version resource of the bytes the digest covers; a hung check is `Timeout`.
pub fn verify_signed_file(file: &File, deadline: Duration) -> Result<SignatureOutcome, SignatureError> {
    let bytes = read_whole(file)?;
    let worker_handle = file.try_clone().map_err(|error| SignatureError::Read { kind: error.kind() })?;
    run_with_deadline(
        deadline,
        Box::new(move || {
            let (code, chain) = wintrust(&worker_handle)?;
            finish(trust_status(code), &bytes, chain, &MICROSOFT_ROOTS)
        }),
    )
}
