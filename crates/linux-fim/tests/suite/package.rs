use crate::plant::{executable, tree};
use crate::support::{fixture, sets};
use crate::types::TestResult;
use linux_fim::classify::content_line;
use linux_fim::limits::{MAX_PATH_BYTES, UNRESOLVED_NAME};
use linux_fim::model::{FileEvidence, FimEvent, PackageOps, PackageVerdict, ToolOutput};
use linux_fim::package::{
    algo_name, annotate, entries_of, exit_code, manager_of, os_exists, os_identity, os_link, os_run, owners_of, parse_line, path_is_exact,
    run_checked, run_first, run_tool, subject_of, token_ok, verdict_for, RpmLine, DPKG_DIVERT, DPKG_QUERY, DPKG_STATUS, RPM,
};
use linux_fim::policy::{kernel_device, policy_names};
use rustix::process::geteuid;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const SHA_BYTES: usize = 32;


const SHA: [u8; SHA_BYTES] = [0xab; SHA_BYTES];


const IDENTITY: (u32, u64) = (7, 9);


const INSTALLED: u64 = 1_700_000_000;


const FAILURE_CODE: i32 = 2;


const OTHER_DEVICE: u32 = 1;


const OTHER_INODE: u64 = 2;


const OVER_TOKEN: usize = 129;


const BIN_PREFIX_BYTES: usize = 6;


const THREE_OWNERS: usize = 3;


const FLAG_COUNT: usize = 3;


const KILLED_BY_SIGNAL: i32 = 9;


const EXITED_WITH_ONE: i32 = 256;


fn hex() -> String {
    "ab".repeat(SHA_BYTES)
}


fn other_hex() -> String {
    "cd".repeat(SHA_BYTES)
}


fn reply(code: i32, stdout: &str) -> io::Result<ToolOutput> {
    Ok(ToolOutput {
        code,
        stdout: stdout.to_string(),
    })
}


fn rpm_text(algo: &str, flags: &str, verify: &str, state: &str, digest: &str, path: &str) -> String {
    format!("H pkg 1.0-1.el9.x86_64 {INSTALLED} {algo}\nF {flags} {verify} {state} {digest} {path}\n")
}


fn plain(path: &str) -> String {
    rpm_text("8", "0", "4294967295", "0", &hex(), path)
}


fn disagreeing(path: &str, algo: &str, flags: &str, verify: &str, digest: &str) -> String {
    format!(
        "{}{}",
        plain(path),
        rpm_text(algo, flags, verify, "0", digest, path).replace("H pkg", "H other")
    )
}


fn scripted(tool: &str, args: &[&str]) -> io::Result<ToolOutput> {
    let last = args.last().copied().unwrap_or("");
    let first = args.first().copied().unwrap_or("");
    match (tool, first, last) {
        (RPM, _, "/usr/bin/failing") => Err(io::Error::other("no rpm")),
        (RPM, _, "/usr/bin/exit2") => reply(FAILURE_CODE, ""),
        (RPM, _, "/usr/bin/unowned") => reply(1, "file /usr/bin/unowned is not owned by any package\n"),
        (RPM, _, "/usr/bin/other-text") => reply(1, "something\n"),
        (RPM, _, "/usr/bin/match") => reply(0, &plain(last)),
        (RPM, _, "/usr/bin/mismatch") => reply(0, &rpm_text("8", "0", "4294967295", "0", &other_hex(), last)),
        (RPM, _, "/usr/bin/cfg") => reply(0, &rpm_text("8", "17", "4294967295", "0", &hex(), last)),
        (RPM, _, "/usr/bin/noverify") => reply(0, &rpm_text("8", "0", "4294967294", "0", &hex(), last)),
        (RPM, _, "/usr/bin/md5") => reply(0, &rpm_text("1", "0", "4294967295", "0", &hex(), last)),
        (RPM, _, "/usr/bin/emptydigest") => reply(0, &rpm_text("8", "0", "4294967295", "0", "", last)),
        (RPM, _, "/usr/bin/replaced") => reply(0, &rpm_text("8", "0", "4294967295", "1", &hex(), last)),
        (RPM, _, "/usr/bin/dup") => reply(0, &format!("{}F 0 4294967295 0 {} {last}\n", plain(last), hex())),
        (RPM, _, "/usr/bin/garbage") => reply(0, "zzz\n"),
        (RPM, _, "/usr/bin/prefixed") => reply(0, &plain("/usr/bin/prefixed-extra")),
        (RPM, _, "/usr/bin/multi") => reply(0, &format!("{}{}", plain(last), plain(last).replace("H pkg", "H other"))),
        (RPM, _, "/usr/bin/multidiff") => reply(0, &disagreeing(last, "8", "0", "4294967295", &other_hex())),
        (RPM, _, "/usr/bin/multiflags") => reply(0, &disagreeing(last, "8", "17", "4294967295", &hex())),
        (RPM, _, "/usr/bin/multiverify") => reply(0, &disagreeing(last, "8", "0", "4294967294", &hex())),
        (RPM, _, "/usr/bin/multialgo") => reply(0, &disagreeing(last, "1", "0", "4294967295", &hex())),
        (DPKG_QUERY, "-S", "/usr/bin/failtext") => reply(1, "no\n"),
        (DPKG_DIVERT, _, "/usr/bin/diverted") => reply(0, "diversion of /usr/bin/diverted to /usr/bin/x.distrib by dash\n"),
        (DPKG_DIVERT, _, "/usr/bin/divfail") => reply(FAILURE_CODE, ""),
        (DPKG_DIVERT, _, _) => reply(0, ""),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgowned") => reply(0, "coreutils: /usr/bin/dpkgowned\n"),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgconf") => reply(0, "pkgc: /usr/bin/dpkgconf\n"),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgmulti") => reply(0, "libc6:amd64, libc6:i386: /usr/bin/dpkgmulti\n"),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgunowned") => reply(1, ""),
        (DPKG_QUERY, "-S", "/usr/bin/searchfail") => reply(FAILURE_CODE, ""),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgdiv") => reply(0, "diversion by dash from: /usr/bin/dpkgdiv\n"),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgweird") => reply(0, "something else\n"),
        (DPKG_QUERY, "-S", "/usr/bin/dpkgbadname") => reply(0, "bad name!: /usr/bin/dpkgbadname\n"),
        (DPKG_QUERY, "-S", "/usr/bin/convfail") => reply(0, "pkgfail: /usr/bin/convfail\n"),
        (DPKG_QUERY, "-W", "pkgc") => reply(0, " /usr/bin/dpkgconf abcd\n /etc/x ef\n"),
        (DPKG_QUERY, "-W", "pkgfail") => reply(1, ""),
        (DPKG_QUERY, "-W", _) => reply(0, " /etc/other 123\n"),
        _ => reply(0, ""),
    }
}


fn same_identity(_path: &str) -> io::Result<(u32, u64)> {
    Ok(IDENTITY)
}


fn other_identity(_path: &str) -> io::Result<(u32, u64)> {
    Ok((OTHER_DEVICE, OTHER_INODE))
}


fn failing_identity(_path: &str) -> io::Result<(u32, u64)> {
    Err(io::Error::other("gone"))
}


fn on_rpm(path: &str) -> bool {
    path != DPKG_STATUS
}


fn on_dpkg(path: &str) -> bool {
    path == DPKG_STATUS
}


fn on_second_rpm_directory(path: &str) -> bool {
    path == "/usr/lib/sysimage/rpm"
}


fn on_nothing(_path: &str) -> bool {
    false
}


fn merged_links(path: &str) -> Option<String> {
    match path {
        "/bin" => Some("usr/bin".to_string()),
        "/sbin" => Some("usr/sbin".to_string()),
        "/lib" => Some("usr/lib".to_string()),
        _ => None,
    }
}


fn split_links(_path: &str) -> Option<String> {
    None
}


fn wrong_link(path: &str) -> Option<String> {
    Some(format!("elsewhere{path}"))
}


fn traversing_link(_path: &str) -> Option<String> {
    Some("usr/bin/../../etc".to_string())
}


fn trailing_slash_link(_path: &str) -> Option<String> {
    Some("usr/bin/".to_string())
}


fn absolute_link(_path: &str) -> Option<String> {
    Some("/usr/bin".to_string())
}


fn extended_link(_path: &str) -> Option<String> {
    Some("usr/binx".to_string())
}


fn multilib_links(path: &str) -> Option<String> {
    match path {
        "/lib32" => Some("usr/lib32".to_string()),
        "/libx32" => Some("usr/libx32".to_string()),
        _ => None,
    }
}


fn rpm_ops() -> PackageOps {
    PackageOps {
        run: scripted,
        identity: same_identity,
        exists: on_rpm,
        link: merged_links,
    }
}


fn dpkg_ops() -> PackageOps {
    PackageOps {
        exists: on_dpkg,
        ..rpm_ops()
    }
}


fn evidence(path: &str) -> FileEvidence {
    FileEvidence {
        path: path.to_string(),
        sha256: SHA,
        identity: IDENTITY,
    }
}


fn rpm_verdict_of(path: &str) -> PackageVerdict {
    verdict_for(path, &evidence(path), &rpm_ops())
}


fn dpkg_verdict_of(path: &str) -> PackageVerdict {
    verdict_for(path, &evidence(path), &dpkg_ops())
}


fn unverified(reason: &'static str) -> PackageVerdict {
    PackageVerdict::Unverified { reason }
}


#[test]
fn an_rpm_digest_equal_to_the_hash_is_a_match_with_package_and_time() -> TestResult {
    assert_eq!(
        rpm_verdict_of("/usr/bin/match"),
        PackageVerdict::Match {
            package: "pkg".into(),
            evra: "1.0-1.el9.x86_64".into(),
            algo: "sha256",
            installed_at: INSTALLED
        }
    );
    Ok(())
}


#[test]
fn an_rpm_digest_that_differs_is_a_mismatch() -> TestResult {
    assert_eq!(
        rpm_verdict_of("/usr/bin/mismatch"),
        PackageVerdict::Mismatch {
            package: "pkg".into(),
            evra: "1.0-1.el9.x86_64".into()
        }
    );
    Ok(())
}


#[test]
fn a_config_file_or_one_verified_without_its_digest_is_config_whatever_the_digest() -> TestResult {
    assert_eq!(rpm_verdict_of("/usr/bin/cfg"), PackageVerdict::Config);
    assert_eq!(rpm_verdict_of("/usr/bin/noverify"), PackageVerdict::Config);
    Ok(())
}


#[test]
fn a_digest_algorithm_other_than_sha256_or_an_empty_digest_is_never_a_match() -> TestResult {
    assert_eq!(rpm_verdict_of("/usr/bin/md5"), PackageVerdict::UnverifiableDigest { algo: "md5" });
    assert_eq!(
        rpm_verdict_of("/usr/bin/emptydigest"),
        PackageVerdict::UnverifiableDigest { algo: "sha256" }
    );
    Ok(())
}


#[test]
fn a_file_state_other_than_normal_or_another_path_in_the_output_is_not_an_owner() -> TestResult {
    assert_eq!(rpm_verdict_of("/usr/bin/replaced"), PackageVerdict::Unowned);
    assert_eq!(rpm_verdict_of("/usr/bin/prefixed"), PackageVerdict::Unowned);
    assert_eq!(rpm_verdict_of("/usr/bin/unowned"), PackageVerdict::Unowned);
    Ok(())
}


#[test]
fn a_duplicate_line_for_one_owner_refuses_the_path() -> TestResult {
    assert_eq!(rpm_verdict_of("/usr/bin/dup"), unverified("duplicate_entry"));
    Ok(())
}


#[test]
fn two_owners_that_agree_are_named_together_and_two_that_differ_are_ambiguous() -> TestResult {
    assert_eq!(
        rpm_verdict_of("/usr/bin/multi"),
        PackageVerdict::Match {
            package: "other,pkg".into(),
            evra: "1.0-1.el9.x86_64,1.0-1.el9.x86_64".into(),
            algo: "sha256",
            installed_at: INSTALLED
        }
    );
    for path in ["multidiff", "multiflags", "multiverify", "multialgo"] {
        assert_eq!(rpm_verdict_of(&format!("/usr/bin/{path}")), PackageVerdict::AmbiguousOwner, "{path}");
    }
    Ok(())
}


#[test]
fn rpm_failures_are_named_for_that_path_alone() -> TestResult {
    assert_eq!(rpm_verdict_of("/usr/bin/failing"), unverified("command_failed"));
    assert_eq!(rpm_verdict_of("/usr/bin/exit2"), unverified("command_failed"));
    assert_eq!(rpm_verdict_of("/usr/bin/other-text"), unverified("command_failed"));
    assert_eq!(rpm_verdict_of("/usr/bin/garbage"), unverified("output_not_parsed"));
    Ok(())
}


#[test]
fn lines_that_do_not_parse_are_refused() -> TestResult {
    let good_file = format!("F 0 4294967295 0 {} /p", hex());
    assert!(matches!(parse_line(&good_file), Some(RpmLine::File(_))));
    assert!(matches!(parse_line("H pkg 1.0-1.x86_64 5 8"), Some(RpmLine::Header(_))));
    let bad = [
        "",
        "X 1",
        "H pkg 1.0 5",
        "H -pkg 1.0 5 8",
        "H pkg -1.0 5 8",
        "H pkg 1.0 x 8",
        "F 0 1 0 zz /p",
        "F 0 1 0 /p",
        "F x 1 0 aa /p",
        "F 0 x 0 aa /p",
        "F 0 1 x aa /p",
        "F 0 1 -1 aa /p",
    ];
    for text in bad {
        assert!(parse_line(text).is_none(), "{text}");
    }
    let long_digest = format!("F 0 1 0 {} /p", "a".repeat(OVER_TOKEN));
    assert!(parse_line(&long_digest).is_none());
    Ok(())
}


#[test]
fn a_file_line_before_any_header_or_an_unparsed_line_refuses_the_output() -> TestResult {
    assert_eq!(entries_of("F 0 1 0 aa /p\n", "/p"), Err("output_not_parsed"));
    assert_eq!(
        entries_of("H pkg 1.0-1.x86_64 5 8\n\nF 0 1 0 aa /p\n", "/p").map(|kept| kept.len()),
        Ok(1)
    );
    Ok(())
}


#[test]
fn a_newline_forged_filename_cannot_give_a_second_match() -> TestResult {
    let forged = format!("{}F 0 4294967295 0 {} /usr/bin/match\n", plain("/usr/bin/x"), hex());
    assert_eq!(entries_of(&forged, "/usr/bin/match").map(|kept| kept.len()), Ok(1));
    let twice = format!("{forged}F 0 4294967295 0 {} /usr/bin/match\n", hex());
    assert_eq!(entries_of(&twice, "/usr/bin/match"), Err("duplicate_entry"));
    Ok(())
}


#[test]
fn algorithm_numbers_have_names_and_an_absent_one_is_unknown() -> TestResult {
    let named = ["1", "2", "8", "9", "10", "(none)"].map(algo_name);
    assert_eq!(named, ["md5", "sha1", "sha256", "sha384", "sha512", "unknown"]);
    Ok(())
}


#[test]
fn dpkg_never_goes_above_unverifiable_digest_and_a_conffile_is_config() -> TestResult {
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgowned"), PackageVerdict::UnverifiableDigest { algo: "md5" });
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgconf"), PackageVerdict::Config);
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgunowned"), PackageVerdict::Unowned);
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgmulti"), PackageVerdict::AmbiguousOwner);
    Ok(())
}


#[test]
fn a_diverted_dpkg_path_and_every_dpkg_failure_are_unverified() -> TestResult {
    assert_eq!(dpkg_verdict_of("/usr/bin/diverted"), unverified("diverted"));
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgdiv"), unverified("diverted"));
    assert_eq!(dpkg_verdict_of("/usr/bin/divfail"), unverified("command_failed"));
    assert_eq!(dpkg_verdict_of("/usr/bin/searchfail"), unverified("command_failed"));
    assert_eq!(dpkg_verdict_of("/usr/bin/failtext"), unverified("command_failed"));
    assert_eq!(dpkg_verdict_of("/usr/bin/convfail"), unverified("command_failed"));
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgweird"), unverified("output_not_parsed"));
    assert_eq!(dpkg_verdict_of("/usr/bin/dpkgbadname"), unverified("output_not_parsed"));
    Ok(())
}


#[test]
fn dpkg_owner_lines_are_read_for_the_exact_path_only() -> TestResult {
    assert_eq!(owners_of("a: /p\n\nb, c:amd64: /p\n", "/p").map(|found| found.len()), Ok(THREE_OWNERS));
    assert_eq!(owners_of("a: /q\n", "/p"), Err("output_not_parsed"));
    Ok(())
}


#[test]
fn the_manager_comes_from_the_database_directories() -> TestResult {
    let mut ops = rpm_ops();
    assert!(manager_of(&ops).is_ok());
    ops.exists = on_second_rpm_directory;
    assert!(manager_of(&ops).is_ok());
    ops.exists = on_nothing;
    assert_eq!(manager_of(&ops).err(), Some("no_package_manager"));
    assert_eq!(rpm_verdict_with(on_nothing), unverified("no_package_manager"));
    Ok(())
}


fn rpm_verdict_with(exists: fn(&str) -> bool) -> PackageVerdict {
    verdict_for("/usr/bin/match", &evidence("/usr/bin/match"), &PackageOps { exists, ..rpm_ops() })
}


#[test]
fn a_path_that_is_not_exact_or_evidence_for_another_path_is_unverified() -> TestResult {
    for path in ["usr/bin/x", "/usr/bin/a b", "/usr/bin/a;b", &format!("/{}", "a".repeat(MAX_PATH_BYTES))] {
        assert!(!path_is_exact(path), "{path}");
        assert_eq!(verdict_for(path, &evidence(path), &rpm_ops()), unverified("path_not_exact"));
    }
    assert_eq!(
        verdict_for("/usr/bin/match", &evidence("/usr/bin/other"), &rpm_ops()),
        unverified("evidence_for_another_path")
    );
    Ok(())
}


#[test]
fn a_file_that_changed_during_the_query_is_unverified() -> TestResult {
    let swapped = PackageOps {
        identity: other_identity,
        ..rpm_ops()
    };
    let gone = PackageOps {
        identity: failing_identity,
        ..rpm_ops()
    };
    assert_eq!(
        verdict_for("/usr/bin/match", &evidence("/usr/bin/match"), &swapped),
        unverified("file_changed")
    );
    assert_eq!(
        verdict_for("/usr/bin/match", &evidence("/usr/bin/match"), &gone),
        unverified("file_changed")
    );
    Ok(())
}


#[test]
fn tokens_start_with_a_letter_or_digit_and_stay_bounded() -> TestResult {
    assert!(token_ok("openssh-server"));
    assert!(token_ok("libc6:amd64"));
    for text in ["", "-x", "a b", "a;b", &"a".repeat(OVER_TOKEN)] {
        assert!(!token_ok(text), "{text}");
    }
    Ok(())
}


fn write_with(path: &str, flags: [bool; FLAG_COUNT], dentry_path: Option<String>) -> FimEvent {
    let [first_flag, second_flag, third_flag] = flags;
    FimEvent::Write {
        path: path.into(),
        process: "/usr/bin/rpm".into(),
        name_match: first_flag,
        mount_ambiguous: second_flag,
        foreign_mount_ns: third_flag,
        dentry_path,
    }
}


fn write_event(path: &str) -> FimEvent {
    write_with(path, [false; FLAG_COUNT], None)
}


fn rename_with(target: &str, flags: [bool; FLAG_COUNT]) -> FimEvent {
    let [first_flag, second_flag, third_flag] = flags;
    FimEvent::Rename {
        source: "/usr/bin/.tmp".into(),
        target: target.into(),
        process: "/usr/bin/rpm".into(),
        honeytoken: first_flag,
        mount_ambiguous: second_flag,
        foreign_mount_ns: third_flag,
        source_dentry: None,
        target_dentry: None,
    }
}


fn rename_event(target: &str) -> FimEvent {
    rename_with(target, [false; FLAG_COUNT])
}


fn annotated(event: &FimEvent, content: bool, path: &str) -> Result<PackageVerdict, Box<dyn std::error::Error>> {
    Ok(annotate(event, content, &evidence(path), &sets()?, &rpm_ops()))
}


#[test]
fn a_content_write_with_an_exact_path_is_annotated() -> TestResult {
    let event = write_event("/usr/bin/match");
    let before = event.clone();
    assert!(matches!(annotated(&event, true, "/usr/bin/match")?, PackageVerdict::Match { .. }));
    assert_eq!(event, before);
    Ok(())
}


#[test]
fn every_other_write_is_not_applicable() -> TestResult {
    assert_eq!(
        annotated(&write_event("/usr/bin/match"), false, "/usr/bin/match")?,
        PackageVerdict::NotApplicable
    );
    let variants = [
        write_with("/usr/bin/match", [true, false, false], None),
        write_with("/usr/bin/match", [false, true, false], None),
        write_with("/usr/bin/match", [false, false, true], None),
        write_with("/usr/bin/match", [false; FLAG_COUNT], Some("/usr/bin/match".into())),
    ];
    for event in variants {
        assert_eq!(annotated(&event, true, "/usr/bin/match")?, PackageVerdict::NotApplicable, "{event:?}");
    }
    Ok(())
}


#[test]
fn a_rename_is_annotated_on_its_declared_target_only() -> TestResult {
    assert!(matches!(
        annotated(&rename_event("/usr/bin/match"), false, "/usr/bin/match")?,
        PackageVerdict::Match { .. }
    ));
    let not_applicable = [
        rename_event("/tmp/elsewhere"),
        rename_event(UNRESOLVED_NAME),
        rename_with("/usr/bin/match", [true, false, false]),
        rename_with("/usr/bin/match", [false, true, false]),
        rename_with("/usr/bin/match", [false, false, true]),
    ];
    for event in not_applicable {
        assert_eq!(annotated(&event, false, "/usr/bin/match")?, PackageVerdict::NotApplicable, "{event:?}");
    }
    Ok(())
}


#[test]
fn removals_links_and_honeytokens_are_not_applicable() -> TestResult {
    let other = [
        FimEvent::Honeytoken {
            path: "/usr/bin/match".into(),
            process: "x".into(),
        },
        FimEvent::Oversized {
            policy: "p".into(),
            bytes: 1,
        },
    ];
    for event in other {
        assert_eq!(subject_of(&event, true, &sets()?), None);
    }
    Ok(())
}


#[test]
fn only_a_content_hook_of_the_fim_policy_is_a_content_line() -> TestResult {
    let policies = policy_names("server");
    assert!(content_line(&fixture("write-passwd.json")?, &policies));
    for name in ["setcap-bin.json", "chmod-shadow.json", "unlink-cron.json"] {
        assert!(!content_line(&fixture(name)?, &policies), "{name}");
    }
    assert!(!content_line(&fixture("write-passwd.json")?, &[]));
    let mknod = fixture("write-passwd.json")?.replace("security_file_permission", "security_path_mknod");
    assert!(mknod.contains("security_path_mknod"));
    assert!(!content_line(&mknod, &policies));
    assert!(!content_line("not json", &policies));
    assert!(!content_line("{}", &policies));
    assert!(!content_line(r#"{"process_kprobe":{}}"#, &policies));
    Ok(())
}


#[test]
fn a_tool_runs_with_its_output_and_exit_code() -> TestResult {
    let echo = executable("echo")?;
    let echo_text = echo.to_str().ok_or("path")?;
    let output = run_tool(echo_text, &["a"], DEADLINE)?;
    assert_eq!(
        output,
        ToolOutput {
            code: 0,
            stdout: "a\n".into()
        }
    );
    assert_eq!(run_tool("/usr/bin/false", &[], DEADLINE)?.code, 1);
    assert!(run_tool("/nonexistent/tool", &[], DEADLINE).is_err());
    assert_eq!(exit_code(ExitStatus::from_raw(KILLED_BY_SIGNAL)), -1);
    assert_eq!(exit_code(ExitStatus::from_raw(EXITED_WITH_ONE)), 1);
    Ok(())
}


#[test]
fn a_tool_that_hangs_or_floods_is_cut() -> TestResult {
    executable("echo")?;
    let hang = format!("{}/tests/fixtures/tetra-hang.sh", env!("CARGO_MANIFEST_DIR"));
    let hung = run_tool(&hang, &[], Duration::ZERO).err().ok_or("a hanging tool succeeded")?;
    assert_eq!(hung.kind(), io::ErrorKind::TimedOut);
    let flood = run_tool("/usr/bin/yes", &[], DEADLINE).err().ok_or("an endless tool succeeded")?;
    assert!(flood.to_string().contains("too long"));
    Ok(())
}


#[test]
fn a_trusted_tool_runs_and_an_untrusted_or_swapped_one_does_not() -> TestResult {
    let dir = tree()?;
    let echo = executable("echo")?;
    let echo_text = echo.to_str().ok_or("path")?;
    let owner = geteuid().as_raw();
    assert_eq!(run_first(echo_text, &["b"], owner, DEADLINE)?.stdout, "b\n");
    assert_eq!(
        run_first("/nonexistent/tool", &[], owner, DEADLINE).err().map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    assert!(run_first("/", &[], owner, DEADLINE).is_err());
    assert!(os_run("/nonexistent/tool", &[]).is_err());
    let handle = core_config::trusted_program::open_trusted_program(&echo, owner)?;
    let decoy = dir.path().join("decoy");
    std::fs::copy(&echo, &decoy)?;
    let decoy_text = decoy.to_str().ok_or("path")?;
    assert!(run_checked(decoy_text, &handle, owner, DEADLINE, &[]).is_err());
    assert!(run_checked("/nonexistent/tool", &handle, owner, DEADLINE, &[]).is_err());
    assert!(run_checked(echo_text, &handle, owner, DEADLINE, &["c"]).is_ok());
    Ok(())
}


#[test]
fn the_real_identity_and_existence_checks_read_the_file_system() -> TestResult {
    let dir = tree()?;
    let file = dir.path().join("f");
    std::fs::write(&file, "x")?;
    let meta = std::fs::metadata(&file)?;
    let text = file.to_str().ok_or("path")?;
    assert_eq!(os_identity(text)?, (kernel_device(meta.dev()), meta.ino()));
    assert!(os_identity("/nonexistent/f").is_err());
    assert!(os_exists(text));
    assert!(!os_exists("/nonexistent/f"));
    assert!(!os_exists("/dev/null/f"));
    Ok(())
}


#[test]
fn a_usrmerge_alias_of_an_unowned_path_gets_the_owners_verdict() -> TestResult {
    let long = format!("/bin/{}", "a".repeat(MAX_PATH_BYTES - BIN_PREFIX_BYTES));
    assert!(matches!(
        verdict_for("/bin/aliasmatch", &evidence("/bin/aliasmatch"), &aliased_ops()),
        PackageVerdict::Match { .. }
    ));
    assert!(matches!(
        verdict_for("/usr/bin/aliasmatch", &evidence("/usr/bin/aliasmatch"), &aliased_ops()),
        PackageVerdict::Match { .. }
    ));
    let owning_long = PackageOps {
        run: long_alias_run,
        ..aliased_ops()
    };
    assert_eq!(verdict_for(&long, &evidence(&long), &owning_long), PackageVerdict::Unowned);
    Ok(())
}


fn aliased_run(tool: &str, args: &[&str]) -> io::Result<ToolOutput> {
    let last = args.last().copied().unwrap_or("");
    match (tool, last) {
        (RPM, "/usr/bin/aliasmatch" | "/usr/opt/aliasmatch" | "/usr/lib32/aliasmatch" | "/usr/libx32/aliasmatch") => reply(0, &plain(last)),
        (RPM, _) => reply(1, &format!("file {last} is not owned by any package\n")),
        _ => scripted(tool, args),
    }
}


fn long_alias_run(tool: &str, args: &[&str]) -> io::Result<ToolOutput> {
    let last = args.last().copied().unwrap_or("");
    match (tool, last.starts_with("/usr/bin/aaaa")) {
        (RPM, true) => reply(0, &plain(last)),
        _ => aliased_run(tool, args),
    }
}


fn aliased_ops() -> PackageOps {
    PackageOps {
        run: aliased_run,
        ..rpm_ops()
    }
}


#[test]
fn an_alias_is_used_only_where_the_system_links_it() -> TestResult {
    for link in [
        split_links,
        wrong_link,
        traversing_link,
        trailing_slash_link,
        absolute_link,
        extended_link,
    ] {
        let ops = PackageOps { link, ..aliased_ops() };
        assert_eq!(
            verdict_for("/bin/aliasmatch", &evidence("/bin/aliasmatch"), &ops),
            PackageVerdict::Unowned
        );
    }
    let outside = verdict_for("/opt/aliasmatch", &evidence("/opt/aliasmatch"), &aliased_ops());
    assert_eq!(outside, PackageVerdict::Unowned);
    let owned = verdict_for("/usr/bin/aliasmatch", &evidence("/usr/bin/aliasmatch"), &aliased_ops());
    assert!(matches!(owned, PackageVerdict::Match { .. }));
    Ok(())
}


#[test]
fn the_multilib_directories_are_aliased_to_their_usr_twins() -> TestResult {
    let ops = PackageOps {
        link: multilib_links,
        ..aliased_ops()
    };
    for path in ["/lib32/aliasmatch", "/libx32/aliasmatch"] {
        assert!(matches!(verdict_for(path, &evidence(path), &ops), PackageVerdict::Match { .. }));
    }
    Ok(())
}


#[test]
fn a_dpkg_alias_is_judged_with_its_own_diversion_check() -> TestResult {
    let verdict = verdict_for("/usr/bin/dpkgowned", &evidence("/usr/bin/dpkgowned"), &dpkg_ops());
    assert!(matches!(verdict, PackageVerdict::UnverifiableDigest { .. }));
    let unowned = verdict_for("/bin/dpkgunowned", &evidence("/bin/dpkgunowned"), &dpkg_ops());
    assert_eq!(unowned, PackageVerdict::Unowned);
    Ok(())
}


#[test]
fn the_real_link_reader_gives_the_text_or_nothing() -> TestResult {
    assert_eq!(os_link("/nonexistent/link"), None);
    assert_eq!(os_link("/etc/passwd"), None);
    let root = tree()?;
    let target = root.path().join("target");
    std::os::unix::fs::symlink("usr/bin", &target)?;
    assert_eq!(os_link(target.to_str().ok_or("path")?), Some("usr/bin".to_string()));
    Ok(())
}
