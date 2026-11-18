use crate::model::HoneytokenKind;


/// Random bytes read from the OS for one decoy: every template draws its characters from them.
pub const RANDOM_BYTES: usize = 512;


pub const UPPER_DIGITS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";


pub const ALPHANUMERIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


pub const FILLER: char = '0';


pub const ACCESS_KEY_CHARS: usize = 16;


pub const SECRET_KEY_CHARS: usize = 40;


pub const KEY_LINE_CHARS: usize = 70;


pub const KEY_LINES: usize = 3;


pub const PASSWORD_CHARS: usize = 16;


pub const PASSWORD_NAMES: [&str; 3] = ["admin", "backup", "root"];


pub const CANARY_CHARS: usize = 32;


/// The number of values one byte takes.
pub const BYTE_VALUES: usize = 256;


/// Bytes read per character wanted: bytes at or over the largest multiple of the alphabet size are rejected, so a window twice the count is ample.
pub const WINDOW_FACTOR: usize = 2;


/// `count` characters of `alphabet` by rejection sampling over the `count * WINDOW_FACTOR` bytes at `start`, padded with `FILLER`.
pub fn symbols(bytes: &[u8], start: usize, count: usize, alphabet: &str) -> String {
    let size = alphabet.chars().count();
    let limit = BYTE_VALUES.checked_rem(size).map_or(0, |excess| BYTE_VALUES - excess);
    bytes
        .iter()
        .skip(start)
        .take(count * WINDOW_FACTOR)
        .map(|byte| usize::from(*byte))
        .filter(|value| *value < limit)
        .filter_map(|value| value.checked_rem(size).and_then(|index| alphabet.chars().nth(index)))
        .chain(std::iter::repeat(FILLER))
        .take(count)
        .collect()
}


/// The text of a decoy of `kind` made from random `bytes`: it looks like the real thing and is a credential for nothing.
pub fn token_content(kind: HoneytokenKind, bytes: &[u8]) -> String {
    match kind {
        HoneytokenKind::AwsCredentials => format!(
            "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\n",
            symbols(bytes, 0, ACCESS_KEY_CHARS, UPPER_DIGITS),
            symbols(bytes, ACCESS_KEY_CHARS * WINDOW_FACTOR, SECRET_KEY_CHARS, ALPHANUMERIC)
        ),
        HoneytokenKind::SshKey => {
            let lines: String = (0..KEY_LINES)
                .map(|line| {
                    format!(
                        "{}\n",
                        symbols(bytes, line * KEY_LINE_CHARS * WINDOW_FACTOR, KEY_LINE_CHARS, ALPHANUMERIC)
                    )
                })
                .collect();
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}-----END OPENSSH PRIVATE KEY-----\n")
        }
        HoneytokenKind::PasswordFile => PASSWORD_NAMES
            .iter()
            .enumerate()
            .map(|(line, name)| {
                format!(
                    "{name}: {}\n",
                    symbols(bytes, line * PASSWORD_CHARS * WINDOW_FACTOR, PASSWORD_CHARS, ALPHANUMERIC)
                )
            })
            .collect(),
        HoneytokenKind::Canary => format!("{}\n", symbols(bytes, 0, CANARY_CHARS, ALPHANUMERIC)),
    }
}
