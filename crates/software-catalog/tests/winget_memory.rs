#![cfg(target_os = "linux")]

use software_catalog::installed_winget::parse_winget_export;
use software_catalog::limits::Limits;
use std::io::Cursor;


const HEAD: &str = r#"{"Sources":[{"SourceDetails":{"Name":"winget","Identifier":"Microsoft.Winget.Source_8wekyb3d8bbwe"},"Packages":[{"PackageIdentifier":"Mozilla.Firefox","Version":"#;


const TAIL: &str = "}]}]}";


const ELEMENT_BYTES: usize = 2;


const HALF: usize = 2;


const THIRD: usize = 3;


const VALUE_BYTES: usize = 15 * 1024 * 1024;


const MAX_GROWTH_KIB: u64 = 20 * 1024;


fn peak_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    Ok(line.split_whitespace().nth(1).ok_or("no value")?.parse()?)
}


fn document(value: &str) -> String {
    format!("{HEAD}{value}{TAIL}")
}


#[test]
fn a_huge_version_value_is_never_materialised() -> Result<(), Box<dyn std::error::Error>> {
    let count = VALUE_BYTES / ELEMENT_BYTES;
    let shapes = [
        format!("[{}0]", "0,".repeat(count)),
        format!("[{}[]]", "[],".repeat(count / HALF)),
        format!(r#"[{}""]"#, r#""","#.repeat(count / HALF)),
        format!(r#"{{{}"k":0}}"#, r#""a":0,"#.repeat(count / THIRD)),
    ];
    let texts: Vec<String> = shapes.iter().map(|shape| document(shape)).collect();
    let before = peak_kib()?;
    let results = texts
        .iter()
        .map(|text| parse_winget_export(Cursor::new(text.as_bytes()), &Limits::default()))
        .collect::<Result<Vec<_>, _>>()?;
    let growth = peak_kib()? - before;
    assert!(results
        .iter()
        .all(|installed| installed.rows.len() == 1 && installed.unreadable_versions == 1));
    assert!(growth < MAX_GROWTH_KIB, "parsing grew the peak by {growth} KiB");
    Ok(())
}
