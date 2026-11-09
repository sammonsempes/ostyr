mod common;


use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::apt::parse_apt;
use patch_inventory::dnf::parse_dnf;
use patch_inventory::model::{Limits, SkipReason};
use patch_inventory::validate::{is_dpkg_architecture, is_dpkg_name, is_plain_text, is_rpm_architecture, is_rpm_name};


const EMPTY: &[u8] = b"";


const EIGHT: usize = 8;


const TWO: usize = 2;


#[test]
fn grammars_accept_real_names_and_refuse_the_rest() -> TestResult {
    assert!(is_dpkg_name("libcurl4t64") && is_dpkg_name("g++-12") && is_dpkg_name("0ad"));
    assert!(!is_dpkg_name("") && !is_dpkg_name("-oAPT") && !is_dpkg_name("Upper") && !is_dpkg_name("a b"));
    assert!(is_dpkg_architecture("amd64") && is_dpkg_architecture("linux-any"));
    assert!(!is_dpkg_architecture("") && !is_dpkg_architecture("amd64\u{200b}"));
    assert!(is_rpm_name("openssl-libs") && is_rpm_name("python3.9") && is_rpm_name("_x") && is_rpm_name("Foo"));
    assert!(!is_rpm_name("") && !is_rpm_name("--exec=x") && !is_rpm_name("a\u{202e}b") && !is_rpm_name("a b"));
    assert!(is_rpm_architecture("x86_64") && !is_rpm_architecture("") && !is_rpm_architecture("x86-64"));
    assert!(is_plain_text("noble-security,noble-updates") && !is_plain_text("") && !is_plain_text("-x") && !is_plain_text("a b"));
    Ok(())
}


#[test]
fn apt_fields_outside_the_grammar_are_malformed() -> TestResult {
    let input = "-oAPT::Update::Pre-Invoke::=x/noble-security 1.0 amd64\n\
                 evil\u{202e}gpj/noble 1.0 amd64\n\
                 a/noble 1.0 amd64\u{200b}\n\
                 a/noble 1.0 AMD64\n\
                 a/-noble 1.0 amd64\n\
                 a/noble -1.0 amd64\n\
                 a/noble 1.0 amd64 [upgradable from: -0.9]\n\
                 a/ 1.0 amd64\n";
    let inventory = parse_apt(&device(), input.as_bytes(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(
        skipped_count(&inventory.skipped, SkipReason::Malformed) + skipped_count(&inventory.skipped, SkipReason::ControlCharacters),
        EIGHT
    );
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::ControlCharacters), TWO_INVISIBLE);
    Ok(())
}


const TWO_INVISIBLE: usize = 2;


#[test]
fn dnf_fields_outside_the_grammar_are_malformed() -> TestResult {
    let updateinfo = "RLSA-1 bugfix --exec=x-1.0-1.x86_64\n\
                      RLSA-1 bugfix a-1.0-1.x86\u{200b}\n\
                      -RLSA-1 bugfix a-1.0-1.x86_64\n\
                      RLSA-1 -x/Sec. a-1.0-1.x86_64\n";
    let check = "--exec=x.x86_64 1.0 repo\nevil\u{202e}gpj.x86_64 1.0 repo\na.x86_64 1.0 -repo\na.x86_64 -1.0 repo\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), check.as_bytes(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(
        skipped_count(&inventory.skipped, SkipReason::Malformed) + skipped_count(&inventory.skipped, SkipReason::ControlCharacters),
        EIGHT
    );
    Ok(())
}


#[test]
fn a_failing_reader_is_an_error_not_a_record() -> TestResult {
    assert!(parse_apt(&device(), FailingReader, &limits()).is_err());
    Ok(())
}


#[test]
fn exactly_max_lines_with_a_final_newline_is_accepted() -> TestResult {
    let two = Limits { max_lines: TWO, ..limits() };
    assert_eq!(
        parse_apt(&device(), "a/b 1.0 amd64\nc/d 1.0 amd64\n".as_bytes(), &two)?.updates.len(),
        TWO
    );
    assert_eq!(parse_apt(&device(), "a/b 1.0 amd64\nc/d 1.0 amd64".as_bytes(), &two)?.updates.len(), TWO);
    assert!(parse_apt(&device(), "a/b 1.0 amd64\nc/d 1.0 amd64\ne/f 1.0 amd64\n".as_bytes(), &two).is_err());
    assert_eq!(
        parse_dnf(&device(), EMPTY, "a.x86_64 1.0 repo\n".as_bytes(), &Limits { max_lines: 1, ..limits() })?
            .updates
            .len(),
        1
    );
    Ok(())
}
