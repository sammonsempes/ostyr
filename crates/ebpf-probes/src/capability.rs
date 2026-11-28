//! What the running kernel lets the file probe see, decided once at load from the kernel release.

use std::io::Read;


/// The kernel release text, one short line.
pub const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";


/// Bytes read from the release file: far above any real release string.
pub const MAX_RELEASE_BYTES: u64 = 256;


/// First kernel (major, minor) whose `FMODE_CREATED` is set before `security_file_open`; Rocky and RHEL 8 (4.18) measured without it.
pub const FIRST_KERNEL_WITH_CREATED: (u32, u32) = (4, 20);


fn leading_number(field: &str) -> Option<u32> {
    let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<u32>().ok()
}


/// True when a file created by a read-only open (`O_CREAT|O_RDONLY`) is not seen: an older or unreadable release counts as unseen.
pub fn create_unseen_for(release: &str) -> bool {
    let mut fields = release.trim().split('.');
    let major = fields.next().and_then(leading_number);
    let minor = fields.next().and_then(leading_number);
    match (major, minor) {
        (Some(major_number), Some(minor_number)) => (major_number, minor_number) < FIRST_KERNEL_WITH_CREATED,
        _ => true,
    }
}


/// Reads at most `MAX_RELEASE_BYTES` from the release file handle and decides `create_unseen_for`.
pub fn create_unseen_from_reader(reader: impl Read) -> Result<bool, std::io::Error> {
    let mut release = String::new();
    reader.take(MAX_RELEASE_BYTES).read_to_string(&mut release)?;
    Ok(create_unseen_for(&release))
}
