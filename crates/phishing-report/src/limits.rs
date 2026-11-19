const KIB: usize = 1024;


const MIB: usize = KIB * KIB;


pub const MAX_MESSAGE_BYTES: usize = 25 * MIB;


pub const MAX_PARTS: usize = 256;


pub const MAX_NESTING: usize = 3;


pub const MAX_HEADERS: usize = 512;


pub const MAX_HEADER_BYTES: usize = 16 * KIB;


pub const MAX_URLS: usize = 500;


pub const MAX_ATTACHMENTS: usize = 64;


pub const MAX_PART_BYTES: usize = 16 * MIB;


pub const MAX_URL_BYTES: usize = 2 * KIB;


pub const MAX_SUBJECT_CHARS: usize = 200;


pub const MAX_NAME_CHARS: usize = 255;


pub const MAX_ADDRESS_BYTES: usize = 320;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub message_bytes: usize,
    pub parts: usize,
    pub nesting: usize,
    pub headers: usize,
    pub header_bytes: usize,
    pub urls: usize,
    pub attachments: usize,
    pub part_bytes: usize,
    pub url_bytes: usize,
    pub subject_chars: usize,
    pub name_chars: usize,
    pub address_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            message_bytes: MAX_MESSAGE_BYTES,
            parts: MAX_PARTS,
            nesting: MAX_NESTING,
            headers: MAX_HEADERS,
            header_bytes: MAX_HEADER_BYTES,
            urls: MAX_URLS,
            attachments: MAX_ATTACHMENTS,
            part_bytes: MAX_PART_BYTES,
            url_bytes: MAX_URL_BYTES,
            subject_chars: MAX_SUBJECT_CHARS,
            name_chars: MAX_NAME_CHARS,
            address_bytes: MAX_ADDRESS_BYTES,
        }
    }
}
