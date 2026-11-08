use crate::types::TestResult;
use policy_validator::model::PathForm;
use policy_validator::path::{canonical_path, command_line_paths, covers, is_path_like, Flavour};


fn form(value: &str) -> Option<PathForm> {
    canonical_path(value).err()
}


fn command_form(value: &str) -> Option<PathForm> {
    command_line_paths(value).err()
}


const PATH_TOKENS: usize = 3;


const CANONICAL: &[&str] = &[
    "/",
    "/srv/app/bin/tool",
    "/srv/app/bin/tool.v2",
    "/opt/my~tool/x",
    r"C:\",
    r"C:\Program Files\Vendor\tool.exe",
];


const REFUSED: &[(&str, PathForm)] = &[
    ("", PathForm::NotAbsolute),
    ("C", PathForm::NotAbsolute),
    ("tool.exe", PathForm::NotAbsolute),
    ("./x", PathForm::NotAbsolute),
    ("..", PathForm::NotAbsolute),
    (r"\Users\bob\evil.exe", PathForm::NotAbsolute),
    (r"%USERPROFILE%\evil.exe", PathForm::NotAbsolute),
    (r"%WINDIR%\Temp\x.exe", PathForm::NotAbsolute),
    ("1:\\x", PathForm::NotAbsolute),
    ("/a/../b", PathForm::DotSegment),
    ("/a/./b", PathForm::DotSegment),
    (r"C:\a\..\b", PathForm::DotSegment),
    ("/var/run/../home/bob/evil", PathForm::DotSegment),
    ("/a/*.exe", PathForm::Wildcard),
    (r"C:\Windows\System32\*.exe", PathForm::Wildcard),
    (r"C:\U*\bob\evil.exe", PathForm::Wildcard),
    ("/srv/a?", PathForm::Wildcard),
    (r"C:\a\%TEMP%\x", PathForm::EnvironmentVariable),
    ("/home/$USER/x", PathForm::EnvironmentVariable),
    ("~/x", PathForm::Tilde),
    ("~", PathForm::Tilde),
    ("/home/~root/x", PathForm::Tilde),
    (r"C:\Progra~1\x", PathForm::ShortName),
    (r"C:\Windows\POWERS~1.EXE", PathForm::ShortName),
    (r"\\server\share\Users\bob\evil.exe", PathForm::Unc),
    (r"\\localhost\C$\x", PathForm::Unc),
    (r"\Device\HarddiskVolume3\Users\bob\evil.exe", PathForm::NtDevice),
    (r"\DEVICE\HarddiskVolume3\Windows\Temp\x.exe", PathForm::NtDevice),
    (r"\Device\Mup\server\share\Users\bob\evil.exe", PathForm::NtDevice),
    (r"\Device\LanmanRedirector\server\share\x", PathForm::NtDevice),
    (r"\\.\GLOBALROOT\Device\Mup\server\share\x", PathForm::NtDevice),
    (r"\\?\C:\Users\x", PathForm::NtDevice),
    (r"\\?\Volume{1}\x", PathForm::NtDevice),
    (r"\\?\GLOBALROOT\Device\x", PathForm::NtDevice),
    (r"\??\C:\x", PathForm::NtDevice),
    ("/??/C:/x", PathForm::NtDevice),
    (r"C:Users\x", PathForm::DriveRelative),
    (r"C:Windows\SysWOW64\WindowsPowerShell\v1.0\", PathForm::DriveRelative),
    ("C:", PathForm::DriveRelative),
    ("C:/Users/x", PathForm::MixedSeparators),
    (r"C:\a/b", PathForm::MixedSeparators),
    (r"/a\b", PathForm::MixedSeparators),
    ("/srv/a:b", PathForm::AlternateStream),
    (r"C:\a\b.txt:evil", PathForm::AlternateStream),
    ("/a/b::$DATA", PathForm::AlternateStream),
    (r"C:\a::$INDEX_ALLOCATION", PathForm::AlternateStream),
    ("/a/b.", PathForm::TrailingDotOrSpace),
    (r"C:\a\b ", PathForm::TrailingDotOrSpace),
    (r"C:\a\evil.exe.", PathForm::TrailingDotOrSpace),
    ("/a//b", PathForm::DoubledSeparator),
    ("//srv/share", PathForm::DoubledSeparator),
    (r"C:\a\\b", PathForm::DoubledSeparator),
    ("/a/", PathForm::TrailingSeparator),
    (r"C:\a\", PathForm::TrailingSeparator),
    (r"C:\Windows\System32\", PathForm::TrailingSeparator),
    ("/a/b\n", PathForm::ControlCharacter),
    ("/a/\tb", PathForm::ControlCharacter),
    ("/a/<b", PathForm::ReservedCharacter),
    ("/a/b|c", PathForm::ReservedCharacter),
    ("/a/\"b", PathForm::ReservedCharacter),
    ("/a/>b", PathForm::ReservedCharacter),
    ("/usr/tmp/../crash/evil", PathForm::DotSegment),
    ("/a/ ", PathForm::TrailingDotOrSpace),
    ("/a/~1", PathForm::Tilde),
];


#[test]
fn canonical_paths_are_accepted() -> TestResult {
    CANONICAL.iter().for_each(|value| assert_eq!(form(value), None, "{value}"));
    Ok(())
}


#[test]
fn every_other_spelling_is_refused_with_its_own_form() -> TestResult {
    REFUSED
        .iter()
        .for_each(|(value, expected)| assert_eq!(form(value), Some(*expected), "{value}"));
    Ok(())
}


#[test]
fn a_canonical_path_is_kept_not_rewritten_except_for_case_matching() -> TestResult {
    let path = canonical_path(r"C:\Users\Bob")?;
    assert_eq!(path.flavour, Flavour::Windows);
    assert_eq!(path.components, vec!["users", "bob"]);
    let root = canonical_path("/")?;
    assert_eq!(root.flavour, Flavour::Posix);
    assert!(root.components.is_empty());
    Ok(())
}


#[test]
fn covers_is_ancestry_of_the_same_flavour() -> TestResult {
    let users = canonical_path(r"C:\Users")?;
    let bob = canonical_path(r"D:\users\bob")?;
    let other = canonical_path(r"C:\Windows")?;
    let posix_users = canonical_path("/Users")?;
    assert!(covers(&users, &bob));
    assert!(covers(&bob, &users));
    assert!(covers(&users, &users));
    assert!(!covers(&users, &other));
    assert!(!covers(&users, &posix_users));
    Ok(())
}


#[test]
fn path_like_tokens_are_found_by_their_characters() -> TestResult {
    ["/x", r"a\b", "a:b", "~x", "%x", "$x", "*x", "x?"]
        .iter()
        .for_each(|token| assert!(is_path_like(token), "{token}"));
    ["--flag", "value", "-v", "a=b"]
        .iter()
        .for_each(|token| assert!(!is_path_like(token), "{token}"));
    Ok(())
}


#[test]
fn a_command_line_yields_its_executable_and_path_tokens() -> TestResult {
    let paths = command_line_paths("/usr/bin/tool --flag value /srv/data   /srv/more")?;
    assert_eq!(paths.len(), PATH_TOKENS);
    Ok(())
}


#[test]
fn a_command_line_refuses_quoting_and_control_characters() -> TestResult {
    assert_eq!(command_form("\"/usr/bin/tool\"x"), Some(PathForm::Quoting));
    assert_eq!(command_form("\"/usr/bin/tool x"), Some(PathForm::Quoting));
    assert_eq!(command_form("\"/usr/bin/tool\" \"x\""), Some(PathForm::Quoting));
    assert_eq!(command_form("/usr/bin/tool 'x'"), Some(PathForm::Quoting));
    assert_eq!(command_form("/usr/bin/tool `x`"), Some(PathForm::Quoting));
    assert_eq!(command_form("/usr/bin/tool ^x"), Some(PathForm::Quoting));
    assert_eq!(command_form("/usr/bin/tool\tx"), Some(PathForm::ControlCharacter));
    assert_eq!(command_form("/usr/bin/tool\nx"), Some(PathForm::ControlCharacter));
    assert_eq!(command_form("/usr/bin/tool\u{a0}x"), Some(PathForm::ControlCharacter));
    Ok(())
}


#[test]
fn a_command_line_is_never_empty_and_starts_with_an_absolute_executable() -> TestResult {
    assert_eq!(command_form(""), Some(PathForm::Empty));
    assert_eq!(command_form("   "), Some(PathForm::Empty));
    assert_eq!(command_form("powershell -enc AAAA"), Some(PathForm::NotAbsolute));
    Ok(())
}


#[test]
fn a_path_glued_to_an_option_is_not_absolute() -> TestResult {
    for value in [
        "/usr/bin/tool -o/tmp/evil",
        "/usr/bin/tool --out=/tmp/x",
        "/usr/bin/tool --out:/tmp/x",
        r"C:\Tools\tool.exe -File:C:\Users\Public\x.ps1",
        "/usr/bin/tool tar -C/tmp",
    ] {
        assert_eq!(command_form(value), Some(PathForm::NotAbsolute), "{value}");
    }
    Ok(())
}


#[test]
fn an_unquoted_executable_with_spaces_is_refused() -> TestResult {
    assert_eq!(
        command_form(r"C:\Program Files\PowerShell\7\pwsh.exe -NoProfile -File x.ps1"),
        Some(PathForm::NotAbsolute)
    );
    assert_eq!(command_form(r"C:\Program Files\Python311\python.exe x.py"), Some(PathForm::NotAbsolute));
    Ok(())
}


#[test]
fn a_path_token_of_a_command_line_is_checked_like_a_path() -> TestResult {
    assert_eq!(command_form("/usr/bin/tool /srv/../etc/x"), Some(PathForm::DotSegment));
    assert_eq!(command_form("/usr/bin/tool /srv/*"), Some(PathForm::Wildcard));
    Ok(())
}


#[test]
fn a_quoted_or_whole_executable_with_spaces_is_parsed() -> TestResult {
    assert_eq!(command_form(r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File x.ps1"#), None);
    assert_eq!(command_form(r#""C:\Program Files\Vendor\app.exe""#), None);
    assert_eq!(command_form(r"C:\Program Files\Vendor\app.exe"), None);
    assert_eq!(command_form(r#""C:\Program Files\V\app.exe" -o C:\x"#), None);
    let quoted = command_line_paths(r#""C:\Program Files\V\app.exe" -x"#)?;
    assert_eq!(quoted.len(), 1);
    Ok(())
}


#[test]
fn a_path_keeps_its_drive_and_its_case_for_exact_matching() -> TestResult {
    let windows = canonical_path(r"C:\Program Files\App.exe")?;
    assert_eq!(windows.drive, Some('c'));
    assert_eq!(windows.exact, vec!["Program Files", "App.exe"]);
    let posix = canonical_path("/Srv/App")?;
    assert_eq!(posix.drive, None);
    assert_eq!(posix.exact, vec!["Srv", "App"]);
    assert!(canonical_path("/")?.exact.is_empty());
    Ok(())
}
