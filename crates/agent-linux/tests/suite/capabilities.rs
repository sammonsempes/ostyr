use crate::types::TestResult;
use agent_linux::capabilities::{
    announce, btf_present, capabilities_event, config_option, detect, effective_mode, leading_number, lsm_state, missing_of, parse_release,
    read_bounded, Capabilities, KernelVersion, Knowledge, Missing, Mode, MAX_SMALL_BYTES,
};
use agent_linux::error::CapabilityError;
use agent_linux::types::SpoolLock;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;


const OVERRIDE_LINE: &str = "CONFIG_BPF_KPROBE_OVERRIDE=y\n";


const LSM_LINE: &str = "CONFIG_BPF_LSM=y\n";


const MEASURED_AT: u64 = 1_700_000_000;


const OVERSIZED: usize = 5000;


const FOUR: u32 = 4;


const FIVE: u32 = 5;


const SEVENTEEN: u32 = 17;


const EIGHTEEN: u32 = 18;


const THREE: u32 = 3;


const SIX: u32 = 6;


const EIGHT: u32 = 8;


const TWO: usize = 2;


const CHUNK_BYTES: usize = 1_048_576;


const CHUNKS: usize = 17;


const BAD_BYTES: [u8; 2] = [0xff, 0xfe];


const LEADING: u32 = 12;


fn put(root: &Path, relative: &str, content: &[u8]) -> TestResult {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(path, content)?;
    Ok(())
}


fn failing_read(_: &Path, _: u64) -> Result<Option<Vec<u8>>, CapabilityError> {
    Err(CapabilityError::Io(std::io::Error::other("injected")))
}


fn version(major: u32, minor: u32) -> Option<KernelVersion> {
    Some(KernelVersion { major, minor })
}


fn caps(kernel: Option<KernelVersion>, btf: bool, kprobe: Knowledge, lsm: Knowledge) -> Capabilities {
    Capabilities {
        kernel,
        kprobe_override: kprobe,
        bpf_lsm_config: Knowledge::Unknown,
        bpf_lsm_active: lsm,
        btf,
    }
}


#[test]
fn ubuntu_like_tree_is_full() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"6.8.0-45-generic\n")?;
    put(
        dir.path(),
        "boot/config-6.8.0-45-generic",
        format!("{OVERRIDE_LINE}{LSM_LINE}").as_bytes(),
    )?;
    put(dir.path(), "sys/kernel/security/lsm", b"lockdown,capability,landlock,yama,apparmor,bpf\n")?;
    put(dir.path(), "sys/kernel/btf/vmlinux", b"btf")?;
    let found = detect(dir.path(), read_bounded);
    assert_eq!(found.kernel, version(SIX, EIGHT));
    assert_eq!(found.bpf_lsm_config, Knowledge::Yes);
    assert_eq!(effective_mode(&found), Mode::Full(vec![]));
    Ok(())
}


#[test]
fn rocky_8_like_tree_is_reduced_through_the_gz_config() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"4.18.0-553.el8_10.x86_64\n")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"# CONFIG_BPF_KPROBE_OVERRIDE is not set\n")?;
    put(dir.path(), "proc/config.gz", &encoder.finish()?)?;
    put(dir.path(), "sys/kernel/security/lsm", b"capability,selinux\n")?;
    put(dir.path(), "sys/kernel/btf/vmlinux", b"btf")?;
    let found = detect(dir.path(), read_bounded);
    assert_eq!(found.kernel, version(FOUR, EIGHTEEN));
    assert_eq!(found.kprobe_override, Knowledge::No);
    assert_eq!(found.bpf_lsm_active, Knowledge::No);
    let mode = effective_mode(&found);
    assert_eq!(mode, Mode::Reduced(vec![Missing::KprobeOverride, Missing::BpfLsm]));
    assert_eq!(mode.to_string(), "reduced");
    assert_eq!(missing_of(&mode).len(), TWO);
    Ok(())
}


#[test]
fn kernel_515_without_btf_is_degraded() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"5.15.0-1\n")?;
    put(dir.path(), "boot/config-5.15.0-1", OVERRIDE_LINE.as_bytes())?;
    let found = detect(dir.path(), read_bounded);
    let mode = effective_mode(&found);
    assert_eq!(mode, Mode::Degraded(vec![Missing::Btf, Missing::BpfLsm]));
    assert_eq!(mode.to_string(), "degraded");
    Ok(())
}


#[test]
fn missing_config_is_unknown_and_the_mode_is_still_computed() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"5.15.0-1\n")?;
    put(dir.path(), "sys/kernel/btf/vmlinux", b"btf")?;
    let found = detect(dir.path(), read_bounded);
    assert_eq!(found.kprobe_override, Knowledge::Unknown);
    assert_eq!(found.bpf_lsm_active, Knowledge::Unknown);
    assert_eq!(effective_mode(&found).to_string(), "reduced");
    Ok(())
}


#[test]
fn an_empty_tree_is_degraded_with_an_unknown_kernel() -> TestResult {
    let dir = tempdir()?;
    let found = detect(dir.path(), read_bounded);
    assert_eq!(found.kernel, None);
    assert_eq!(effective_mode(&found), Mode::Degraded(vec![Missing::Kernel]));
    Ok(())
}


#[test]
fn oversized_files_are_refused() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "big", &vec![b'a'; OVERSIZED])?;
    let refused = read_bounded(&dir.path().join("big"), MAX_SMALL_BYTES);
    assert!(matches!(refused, Err(CapabilityError::TooLarge(_, _))));
    assert!(refused.is_err_and(|error| error.to_string().contains("larger")));
    put(dir.path(), "proc/sys/kernel/osrelease", &vec![b'5'; OVERSIZED])?;
    assert_eq!(detect(dir.path(), read_bounded).kernel, None);
    Ok(())
}


#[test]
fn an_oversized_gz_config_is_unknown() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"5.15.0\n")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    let chunk = vec![b'a'; CHUNK_BYTES];
    (0..CHUNKS).try_for_each(|_| encoder.write_all(&chunk))?;
    put(dir.path(), "proc/config.gz", &encoder.finish()?)?;
    assert_eq!(detect(dir.path(), read_bounded).kprobe_override, Knowledge::Unknown);
    Ok(())
}


#[test]
fn a_corrupt_gz_and_non_utf8_files_are_unknown() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"5.15.0\n")?;
    put(dir.path(), "proc/config.gz", b"not gzip")?;
    put(dir.path(), "sys/kernel/security/lsm", &BAD_BYTES)?;
    let found = detect(dir.path(), read_bounded);
    assert_eq!((found.kprobe_override, found.bpf_lsm_active), (Knowledge::Unknown, Knowledge::Unknown));
    Ok(())
}


#[test]
fn a_release_with_a_slash_never_names_a_config_path() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"../../x\n")?;
    assert_eq!(detect(dir.path(), read_bounded).kernel, None);
    Ok(())
}


#[test]
fn failing_reads_and_btf_checks_are_unknown_not_errors() -> TestResult {
    let dir = tempdir()?;
    let found = detect(dir.path(), failing_read);
    assert_eq!(found.kernel, None);
    put(dir.path(), "sys/kernel", b"a file, not a directory")?;
    assert!(!btf_present(dir.path()));
    Ok(())
}


#[test]
fn a_directory_where_a_file_is_expected_is_an_error() -> TestResult {
    let dir = tempdir()?;
    assert!(read_bounded(dir.path(), MAX_SMALL_BYTES).is_err());
    Ok(())
}


#[test]
fn mode_boundaries() -> TestResult {
    let table = [
        (version(FOUR, SEVENTEEN), "degraded"),
        (version(FOUR, EIGHTEEN), "reduced"),
        (version(FIVE, THREE), "reduced"),
        (version(FIVE, FOUR), "full"),
        (None, "degraded"),
    ];
    table.iter().try_for_each(|(kernel, expected)| -> TestResult {
        let mode = effective_mode(&caps(*kernel, true, Knowledge::Yes, Knowledge::No));
        assert_eq!(&mode.to_string(), expected);
        Ok(())
    })?;
    assert_eq!(
        effective_mode(&caps(version(FIVE, FOUR), true, Knowledge::No, Knowledge::Yes)).to_string(),
        "full"
    );
    assert_eq!(
        effective_mode(&caps(version(FIVE, FOUR), true, Knowledge::No, Knowledge::No)).to_string(),
        "reduced"
    );
    assert_eq!(
        effective_mode(&caps(version(FIVE, THREE), false, Knowledge::Yes, Knowledge::Yes)).to_string(),
        "reduced"
    );
    assert_eq!(
        effective_mode(&caps(version(FIVE, FOUR), false, Knowledge::Yes, Knowledge::Yes)).to_string(),
        "degraded"
    );
    Ok(())
}


#[test]
fn parsers() -> TestResult {
    assert_eq!(parse_release("5.4-rc1"), version(FIVE, FOUR));
    assert_eq!(parse_release("5"), None);
    assert_eq!(parse_release("x.1"), None);
    assert_eq!(parse_release("5.y"), None);
    assert_eq!(leading_number("12abc"), Some(LEADING));
    assert_eq!(config_option(Some("CONFIG_BPF_LSM=y"), "CONFIG_BPF_LSM"), Knowledge::Yes);
    assert_eq!(config_option(Some("CONFIG_BPF_LSM=m"), "CONFIG_BPF_LSM"), Knowledge::No);
    assert_eq!(config_option(None, "X"), Knowledge::Unknown);
    assert_eq!(lsm_state(Some("a,bpf")), Knowledge::Yes);
    assert_eq!(lsm_state(Some("a,bpfx")), Knowledge::No);
    assert_eq!(lsm_state(None), Knowledge::Unknown);
    assert_eq!(Missing::Kernel.to_string(), "kernel");
    assert_eq!(Missing::Btf.to_string(), "btf");
    assert_eq!(Missing::KprobeOverride.to_string(), "kprobe_override");
    assert_eq!(Missing::BpfLsm.to_string(), "bpf_lsm");
    assert_eq!(Mode::Full(vec![]).to_string(), "full");
    Ok(())
}


#[test]
fn announce_spools_one_event_and_returns_the_mode() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "proc/sys/kernel/osrelease", b"4.18.0-1\n")?;
    let spool = dir.path().join("spool");
    let mode = announce(dir.path(), &spool, &SpoolLock::default(), read_bounded, MEASURED_AT)?;
    assert_eq!(mode.to_string(), "reduced");
    let text = fs::read_to_string(&spool)?;
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("agent.capabilities") && text.contains("\"mode\":\"reduced\"") && text.contains("1700000000"));
    let event = capabilities_event(
        &caps(None, false, Knowledge::No, Knowledge::No),
        &Mode::Degraded(vec![Missing::Kernel]),
        1,
    );
    assert!(event.contains("\"kernel\":\"unknown\""));
    Ok(())
}


#[test]
fn announce_fails_when_the_spool_cannot_be_written() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("missing-dir").join("spool");
    assert!(announce(dir.path(), &spool, &SpoolLock::default(), read_bounded, MEASURED_AT).is_err());
    Ok(())
}


#[test]
fn a_path_through_a_file_is_an_error_not_an_absence() -> TestResult {
    let dir = tempdir()?;
    put(dir.path(), "plain", b"x")?;
    assert!(matches!(
        read_bounded(&dir.path().join("plain").join("child"), MAX_SMALL_BYTES),
        Err(CapabilityError::Io(_))
    ));
    Ok(())
}
