#[path = "common/types.rs"]
mod types;


use hardware_health::error::FetchError;
use hardware_health::redfish_devices::{base_of, is_base_url, is_username, parse_devices};
use types::TestResult;


const VALID: &str = "devices:\n  - name: bmc1\n    base_url: \"https://10.0.0.5:443/\"\n    ca_file: /etc/ca.pem\n    username: monitor\n    password_file: /etc/pw\n    timeout_ms: 5000\n";


const INSECURE: &str = "devices:\n  - name: bmc2\n    base_url: \"https://bmc2.lab:8443\"\n    insecure_skip_verify: true\n    username: monitor\n    password_file: /etc/pw\n    timeout_ms: 1000\n";


const OVER_DEVICES: usize = 513;


const OVER_HOST: usize = 5000;


const OVER_USERNAME: usize = 65;


const OVER_BYTES: usize = 262_145;


fn refused(text: &str) -> Result<FetchError, Box<dyn std::error::Error>> {
    Ok(parse_devices(text).err().ok_or("accepted")?)
}


#[test]
fn a_valid_file_loads_and_the_base_url_loses_its_trailing_slash() -> TestResult {
    let devices = parse_devices(VALID)?;
    assert_eq!(devices.len(), 1);
    assert_eq!(base_of(devices.first().ok_or("none")?), "https://10.0.0.5:443");
    let insecure = parse_devices(INSECURE)?;
    assert!(insecure.first().ok_or("none")?.insecure_skip_verify);
    Ok(())
}


#[test]
fn every_invalid_field_is_refused_by_name() -> TestResult {
    let cases = [
        ("name: bmc1", "name: -x", "name"),
        ("https://10.0.0.5:443/", "http://10.0.0.5:443/", "base_url"),
        ("https://10.0.0.5:443/", "https://u:p@10.0.0.5:443/", "base_url"),
        ("https://10.0.0.5:443/", "https://10.0.0.5:443/x", "base_url"),
        ("https://10.0.0.5:443/", "https://10.0.0.5:443/?a=b", "base_url"),
        (
            "ca_file: /etc/ca.pem",
            "insecure_skip_verify: true\n    ca_file: /etc/ca.pem",
            "ca_file or insecure_skip_verify",
        ),
        ("    ca_file: /etc/ca.pem\n", "", "ca_file or insecure_skip_verify"),
        ("ca_file: /etc/ca.pem", "ca_file: \"\"", "ca_file"),
        ("username: monitor", "username: \"a:b\"", "username"),
        ("username: monitor", "username: \"\"", "username"),
        ("password_file: /etc/pw", "password_file: \"\"", "password_file"),
        ("timeout_ms: 5000", "timeout_ms: 999", "timeout_ms"),
        ("timeout_ms: 5000", "timeout_ms: 60001", "timeout_ms"),
    ];
    cases.iter().try_for_each(|(from, to, field)| -> TestResult {
        let error = refused(&VALID.replace(from, to))?;
        assert!(
            matches!(error, FetchError::InvalidDevice { field: found, .. } if found == *field),
            "{to}: {error:?}"
        );
        Ok(())
    })
}


#[test]
fn the_file_is_bounded_strict_and_unique() -> TestResult {
    let one = VALID.trim_start_matches("devices:\n");
    let many = format!("devices:\n{}", one.replace("bmc1", "bmcX").repeat(OVER_DEVICES));
    assert!(matches!(refused(&many)?, FetchError::TooManyDevices { .. }));
    assert!(matches!(refused(&" ".repeat(OVER_BYTES))?, FetchError::DevicesTooLarge { .. }));
    assert!(matches!(refused(&format!("{VALID}extra: 1\n"))?, FetchError::Devices(_)));
    assert!(matches!(
        refused(&VALID.replace("timeout_ms: 5000", "timeout_ms: 5000\n    shell: x"))?,
        FetchError::Devices(_)
    ));
    assert!(matches!(
        refused(&format!("{VALID}{one}"))?,
        FetchError::InvalidDevice { field: "name repeated", .. }
    ));
    let capped: String = std::iter::once("devices:\n".to_owned())
        .chain((0..OVER_DEVICES - 1).map(|index| one.replace("bmc1", &format!("bmc{index}"))))
        .collect();
    assert_eq!(parse_devices(&capped)?.len(), OVER_DEVICES - 1);
    Ok(())
}


#[test]
fn the_text_grammars() -> TestResult {
    assert!(is_base_url("https://h:1"));
    assert!(!is_base_url("https://"));
    assert!(!is_base_url("ftp://h"));
    assert!(!is_base_url(&format!("https://{}", "h".repeat(OVER_HOST))));
    assert!(is_username("a.b_c@d-e"));
    assert!(!is_username(&"a".repeat(OVER_USERNAME)));
    assert!(!is_username("a b"));
    Ok(())
}
