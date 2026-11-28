//! The break-glass listing of `ostyr-auth breakglass-status`: names, passkey counts and last use, never a secret (spec section 15).

use crate::error::AuthError;
use crate::service::{is_break_glass, require, transact, Context, State};
use std::io::Write;
use time::OffsetDateTime;


pub const ACTION_BREAKGLASS_STATUS: &str = "auth.breakglass.status";


pub const BREAKGLASS_TARGET: &str = "break-glass";


pub const NO_PASSKEY: &str = "no_passkey";


pub const NEVER_USED: &str = "never";


/// A name restricted to `[A-Za-z0-9._~%-]`: every other byte becomes `%XX`, so the line can be pasted into a shell.
pub fn shell_inert(text: &str) -> String {
    text.bytes().fold(String::new(), |mut encoded, byte| {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
        encoded
    })
}


pub fn status_line(state: &State, username: &str) -> String {
    let credentials = state.credentials.get(username).map_or(&[][..], Vec::as_slice);
    let last_used = credentials.iter().filter_map(|credential| credential.last_used).max();
    let used = last_used.map_or_else(|| NEVER_USED.to_owned(), |seconds| seconds.to_string());
    let line = format!("{} {} {used}", shell_inert(username), credentials.len());
    if credentials.is_empty() {
        format!("{line} {NO_PASSKEY}")
    } else {
        line
    }
}


/// One line per break-glass account under the catalog in use; allowed for `users.manage`, audited with the count only, the store untouched.
pub fn breakglass_status<Output: Write>(
    state: &mut State,
    context: &Context<Output>,
    now: OffsetDateTime,
    token: &str,
) -> Result<Vec<String>, AuthError> {
    transact(
        state,
        context,
        now,
        token,
        ACTION_BREAKGLASS_STATUS,
        |_| BREAKGLASS_TARGET.to_owned(),
        |working, acting| {
            require(acting, acting.manager).map(|()| {
                let lines: Vec<String> = working
                    .accounts
                    .keys()
                    .filter(|username| is_break_glass(&working.accounts, context.catalog, username))
                    .map(|username| status_line(working, username))
                    .collect();
                let count = lines.len().to_string();
                (lines, vec![("count", count)])
            })
        },
    )
}
