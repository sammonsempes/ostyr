use crate::model::HoneytokenKind;


/// Random bytes read from the OS for one decoy: every template draws its characters from them.
pub const RANDOM_BYTES: usize = 256;


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


/// `count` characters of `alphabet` chosen by the bytes from `start` on, one per byte.
pub fn symbols(bytes: &[u8], start: usize, count: usize, alphabet: &str) -> String {
    let size = alphabet.chars().count();
    bytes
        .iter()
        .skip(start)
        .take(count)
        .map(|byte| {
            usize::from(*byte)
                .checked_rem(size)
                .and_then(|index| alphabet.chars().nth(index))
                .unwrap_or(FILLER)
        })
        .collect()
}


/// The text of a decoy of `kind` made from random `bytes`: it looks like the real thing and is a credential for nothing.
pub fn token_content(kind: HoneytokenKind, bytes: &[u8]) -> String {
    match kind {
        HoneytokenKind::AwsCredentials => format!(
            "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\n",
            symbols(bytes, 0, ACCESS_KEY_CHARS, UPPER_DIGITS),
            symbols(bytes, ACCESS_KEY_CHARS, SECRET_KEY_CHARS, ALPHANUMERIC)
        ),
        HoneytokenKind::SshKey => {
            let lines: String = (0..KEY_LINES)
                .map(|line| format!("{}\n", symbols(bytes, line * KEY_LINE_CHARS, KEY_LINE_CHARS, ALPHANUMERIC)))
                .collect();
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}-----END OPENSSH PRIVATE KEY-----\n")
        }
        HoneytokenKind::PasswordFile => PASSWORD_NAMES
            .iter()
            .enumerate()
            .map(|(line, name)| format!("{name}: {}\n", symbols(bytes, line * PASSWORD_CHARS, PASSWORD_CHARS, ALPHANUMERIC)))
            .collect(),
        HoneytokenKind::Canary => format!("{}\n", symbols(bytes, 0, CANARY_CHARS, ALPHANUMERIC)),
    }
}
