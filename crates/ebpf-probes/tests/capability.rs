use ebpf_probes::capability::{create_unseen_for, create_unseen_from_reader, FIRST_KERNEL_WITH_CREATED, MAX_RELEASE_BYTES};
use std::error::Error;
use std::io::{self, Read};


const OVERSIZE_FACTOR: usize = 4;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


#[test]
fn the_rhel_8_kernel_is_flagged_and_the_measured_newer_kernels_are_not() -> Result<(), Box<dyn Error>> {
    assert!(create_unseen_for("4.18.0-553.el8_10.x86_64\n"));
    assert!(!create_unseen_for("5.14.0-741.el9.x86_64\n"));
    assert!(!create_unseen_for("6.8.0-151-generic"));
    assert!(!create_unseen_for("7.0.0-38-generic"));
    assert!(!create_unseen_for("6.1.0-13-amd64"));
    Ok(())
}


#[test]
fn the_boundary_release_is_the_first_one_without_the_flag() -> Result<(), Box<dyn Error>> {
    let (major, minor) = FIRST_KERNEL_WITH_CREATED;
    assert!(!create_unseen_for(&format!("{major}.{minor}.0")));
    assert!(create_unseen_for(&format!("{major}.{}.99", minor - 1)));
    assert!(create_unseen_for("3.10.0-1160.el7.x86_64"));
    assert!(!create_unseen_for("10.0.0"));
    Ok(())
}


#[test]
fn a_release_with_a_suffix_on_the_minor_is_read_by_its_leading_digits() -> Result<(), Box<dyn Error>> {
    assert!(!create_unseen_for("6.8-rc1"));
    assert!(create_unseen_for("4.18-rc1"));
    Ok(())
}


#[test]
fn an_unparseable_or_empty_release_counts_as_unseen() -> Result<(), Box<dyn Error>> {
    assert!(create_unseen_for(""));
    assert!(create_unseen_for("garbage"));
    assert!(create_unseen_for("6"));
    assert!(create_unseen_for("6.x.1"));
    assert!(create_unseen_for("x.8.0"));
    assert!(create_unseen_for("99999999999.8.0"));
    Ok(())
}


#[test]
fn a_reader_is_decided_and_a_failing_reader_is_an_error() -> Result<(), Box<dyn Error>> {
    assert!(create_unseen_from_reader(&b"4.18.0-553\n"[..])?);
    assert!(!create_unseen_from_reader(&b"6.8.0-151-generic\n"[..])?);
    assert!(create_unseen_from_reader(FailingReader).is_err());
    assert!(create_unseen_from_reader(&INVALID_UTF8[..]).is_err());
    Ok(())
}


#[test]
fn a_reader_is_read_only_up_to_the_cap() -> Result<(), Box<dyn Error>> {
    let filler = usize::try_from(MAX_RELEASE_BYTES)?;
    let mut text = " ".repeat(filler);
    text.push_str("6.8.0");
    assert!(create_unseen_from_reader(text.as_bytes())?);
    let mut padded = "6.8.0 ".to_string();
    padded.push_str(&"x".repeat(filler * OVERSIZE_FACTOR));
    assert!(!create_unseen_from_reader(padded.as_bytes())?);
    Ok(())
}
