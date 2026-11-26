#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use cloud_posture::kubeconfig::{
    add_seals, check_content, create_memfd, read_checked, seal_bytes, seal_with, write_bytes, MAX_ENTRIES, MAX_KUBECONFIG_BYTES,
};
use cloud_posture::model::KubeconfigFault;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use types::TestResult;


const GOOD: &str = "apiVersion: v1\nkind: Config\npreferences: {}\nclusters:\n- name: a\n  cluster:\n    server: https://127.0.0.1:6443\n    certificate-authority-data: AAAA\n    tls-server-name: x\n\
users:\n- name: a\n  user:\n    client-certificate-data: AAAA\n    client-key-data: AAAA\n    token: MARKER\n\
contexts:\n- name: a\n  context:\n    cluster: a\n    user: a\n    namespace: n\ncurrent-context: a\n";


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const EMPTY: &str = "apiVersion: v1\nkind: Config\n";


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("denied"))
    }
}


fn with_user(user: &str) -> String {
    format!("users:\n- name: a\n  user:\n    {user}\n")
}


fn with_cluster(cluster: &str) -> String {
    format!("clusters:\n- name: a\n  cluster:\n    {cluster}\n")
}


fn fault(text: &str) -> Option<KubeconfigFault> {
    check_content(text.as_bytes()).err()
}


#[test]
fn a_clean_kubeconfig_and_an_empty_one_pass() -> TestResult {
    assert_eq!(fault(GOOD), None);
    assert_eq!(fault(EMPTY), None);
    Ok(())
}


#[test]
fn a_command_a_plugin_and_every_file_path_are_refused_by_name() -> TestResult {
    assert_eq!(fault(&with_user("exec:\n      command: /tmp/x")), Some(KubeconfigFault::Exec));
    assert_eq!(
        fault(&with_user("auth-provider:\n      name: gcp\n      config:\n        cmd-path: /tmp/x")),
        Some(KubeconfigFault::AuthProvider)
    );
    assert_eq!(fault(&with_user("tokenFile: /etc/shadow")), Some(KubeconfigFault::FilePath));
    assert_eq!(fault(&with_user("client-key: /srv/secrets/other/key")), Some(KubeconfigFault::FilePath));
    assert_eq!(
        fault(&with_user("client-certificate: /srv/secrets/other/crt")),
        Some(KubeconfigFault::FilePath)
    );
    assert_eq!(fault(&with_cluster("certificate-authority: /etc/ca")), Some(KubeconfigFault::FilePath));
    assert_eq!(fault(&with_cluster("proxy-url: http://127.0.0.1:1")), Some(KubeconfigFault::ProxyUrl));
    let both = format!("{}{}", with_cluster("server: https://x"), with_user("exec:\n      command: /tmp/x"));
    assert_eq!(fault(&both), Some(KubeconfigFault::Exec));
    Ok(())
}


#[test]
fn an_unknown_key_or_a_wrong_shape_is_refused() -> TestResult {
    assert_eq!(fault(&with_user("username: a")), Some(KubeconfigFault::Shape));
    assert_eq!(fault(&with_cluster("insecure-skip-tls-verify: true")), Some(KubeconfigFault::Shape));
    assert_eq!(fault("extensions: []\n"), Some(KubeconfigFault::Shape));
    assert_eq!(fault("preferences:\n  colors: true\n"), Some(KubeconfigFault::Shape));
    assert_eq!(fault("contexts:\n- name: a\n  context:\n    extra: b\n"), Some(KubeconfigFault::Shape));
    assert_eq!(fault("- a\n- b\n"), Some(KubeconfigFault::Shape));
    assert_eq!(fault("users:\n- name: a\n"), Some(KubeconfigFault::Shape));
    Ok(())
}


#[test]
fn yaml_features_and_bytes_that_hide_a_key_are_refused() -> TestResult {
    let hidden = [
        "users:\n- name: a\n  user: !!map\n    exec: {}\n",
        "x: &a\n  command: c\nusers:\n- name: a\n  user:\n    exec: *a\n",
        "users:\n- name: a\n  user:\n    <<: {exec: {}}\n",
        "users:\n- name: a\n  user:\n    \"ex\\u0065c\": {}\n",
        "users:\n- name: a\n  user:\n    token: |\n      abc\n",
        "users:\n- name: a\n  user:\n    token: x\r\n    exec: {}\r",
        "users:\n- name: \u{e9}\n",
        "users:\n- name: a\u{0}\n",
        "a: b\n---\nc: d\n",
        "users:\n- name: a\n  user:\n    exec: {}\n    exec: {}\n",
    ];
    hidden.iter().try_for_each(|text| -> TestResult {
        assert!(matches!(fault(text), Some(KubeconfigFault::Bytes | KubeconfigFault::Shape)), "{text}");
        Ok(())
    })?;
    assert_eq!(check_content(&NOT_UTF8).err(), Some(KubeconfigFault::Bytes));
    Ok(())
}


#[test]
fn a_list_over_the_cap_is_refused_before_any_entry_is_built() -> TestResult {
    let entries = "- {}\n".repeat(MAX_ENTRIES + 1);
    assert_eq!(fault(&format!("clusters:\n{entries}")), Some(KubeconfigFault::TooMany));
    assert_eq!(fault(&format!("users:\n{entries}")), Some(KubeconfigFault::TooMany));
    assert_eq!(fault(&format!("contexts:\n{entries}")), Some(KubeconfigFault::TooMany));
    let at_cap = "- name: a\n  context: {}\n".repeat(MAX_ENTRIES);
    assert_eq!(fault(&format!("contexts:\n{at_cap}")), None);
    Ok(())
}


#[test]
fn a_secret_marker_never_reaches_a_refusal() -> TestResult {
    let marker = "MARKER-SECRET-TOKEN";
    let bodies = [
        format!("users:\n- name: a\n  user:\n    token: {marker}\n    exec: {{}}\n"),
        format!("users:\n- name: a\n  user:\n    token: {marker}\n    extra: {marker}\n"),
        format!("users:\n- name: a\n  user:\n    token: [{marker}\n"),
        format!("users:\n- name: a\n  user:\n    token: &{marker} x\n"),
        format!("users:\n- name: a\n  user:\n    token: {marker}\n    exec: {marker}\n"),
    ];
    bodies.iter().try_for_each(|body| -> TestResult {
        let error = check_content(body.as_bytes()).err().ok_or("accepted")?;
        let text = format!("{error:?} {error:#?}");
        assert!(!text.contains(marker));
        Ok(())
    })
}


#[test]
fn the_read_is_bounded_and_a_failing_read_is_typed() -> TestResult {
    assert_eq!(read_checked(&mut &b"abc"[..]).ok(), Some(b"abc".to_vec()));
    let at_cap = vec![b'a'; usize::try_from(MAX_KUBECONFIG_BYTES)?];
    assert_eq!(read_checked(&mut &at_cap[..]).map(|bytes| bytes.len()).ok(), Some(at_cap.len()));
    let over = vec![b'a'; usize::try_from(MAX_KUBECONFIG_BYTES)? + 1];
    assert_eq!(read_checked(&mut &over[..]).err(), Some(KubeconfigFault::TooLarge));
    assert_eq!(read_checked(&mut Failing).err(), Some(KubeconfigFault::Unreadable));
    Ok(())
}


#[test]
fn the_sealed_copy_holds_the_checked_bytes_and_cannot_change() -> TestResult {
    let mut sealed = seal_bytes(GOOD.as_bytes())?;
    let path = format!("/proc/{}/fd/{}", std::process::id(), sealed.as_raw_fd());
    assert!(std::fs::read_link(&path)?.to_string_lossy().contains("memfd:"));
    assert_eq!(std::fs::read_to_string(&path)?, GOOD);
    assert!(std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|mut other| other.write_all(b"x"))
        .is_err());
    assert!(sealed.write_all(b"x").is_err());
    assert!(sealed.set_len(0).is_err());
    assert!(sealed.set_len(u64::try_from(GOOD.len())? + 1).is_err());
    let mut again = String::new();
    std::fs::File::open(&path)?.read_to_string(&mut again)?;
    assert_eq!(again, GOOD);
    Ok(())
}


fn no_memfd() -> std::io::Result<std::fs::File> {
    Err(std::io::Error::other("memfd"))
}


fn no_write(_file: &mut std::fs::File, _bytes: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::other("write"))
}


fn no_seal(_file: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::Error::other("seal"))
}


#[test]
fn each_sealing_step_fails_alone_and_is_reported() -> TestResult {
    assert!(seal_with(no_memfd, write_bytes, add_seals, b"x").is_err());
    assert!(seal_with(create_memfd, no_write, add_seals, b"x").is_err());
    assert!(seal_with(create_memfd, write_bytes, no_seal, b"x").is_err());
    assert!(seal_with(create_memfd, write_bytes, add_seals, b"x").is_ok());
    Ok(())
}
