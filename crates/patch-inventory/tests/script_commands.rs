#[path = "common/types.rs"]
mod types;


use patch_inventory::wua_script::WUA_SEARCH_SCRIPT;
use types::TestResult;


pub const WUA_TOKENS: [&str; 97] = [
    r#"-ComObject"#,
    r#"-Compress"#,
    r#"-Depth"#,
    r#"-ErrorAction"#,
    r#"-InputObject"#,
    r#"-f"#,
    r#".Search"#,
    r#"0"#,
    r#"0"#,
    r#"4"#,
    r#"C"#,
    r#"C"#,
    r#"CategoryIDs"#,
    r#"Console"#,
    r#"Console"#,
    r#"ErrorActionPreference"#,
    r#"IsHidden"#,
    r#"IsInstalled"#,
    r#"IsMandatory"#,
    r#"KBArticleIDs"#,
    r#"Microsoft.PowerShell.Core\ForEach-Object"#,
    r#"Microsoft.PowerShell.Utility\ConvertTo-Json"#,
    r#"Microsoft.PowerShell.Utility\New-Object"#,
    r#"Microsoft.PowerShell.Utility\New-Object"#,
    r#"Microsoft.PowerShell.Utility\Remove-TypeData"#,
    r#"Microsoft.Update.Session"#,
    r#"MsrcSeverity"#,
    r#"Out.Write"#,
    r#"OutputEncoding"#,
    r#"PSModulePath"#,
    r#"Path"#,
    r#"ProgressPreference"#,
    r#"RebootBehavior"#,
    r#"Replace"#,
    r#"ResultCode"#,
    r#"RevisionNumber"#,
    r#"SilentlyContinue"#,
    r#"SilentlyContinue"#,
    r#"Software"#,
    r#"Stop"#,
    r#"System.Array"#,
    r#"System.Text.UTF8Encoding"#,
    r#"Title"#,
    r#"Type"#,
    r#"UpdateID"#,
    r#"Updates"#,
    r#"\Windows\System32"#,
    r#"\Windows\System32\WindowsPowerShell\v1.0\Modules"#,
    r#"\u"#,
    r#"\u007F-\uFFFF"#,
    r#"_.CategoryID"#,
    r#"and"#,
    r#"bool"#,
    r#"bool"#,
    r#"char"#,
    r#"env"#,
    r#"env"#,
    r#"envelope"#,
    r#"envelope"#,
    r#"false"#,
    r#"foreach"#,
    r#"in"#,
    r#"int"#,
    r#"int"#,
    r#"int"#,
    r#"int"#,
    r#"json"#,
    r#"json"#,
    r#"m"#,
    r#"m.Value"#,
    r#"object"#,
    r#"param"#,
    r#"pscustomobject"#,
    r#"pscustomobject"#,
    r#"regex"#,
    r#"result"#,
    r#"result.ResultCode"#,
    r#"result.Updates"#,
    r#"session"#,
    r#"session.CreateUpdateSearcher"#,
    r#"string"#,
    r#"string"#,
    r#"string"#,
    r#"string"#,
    r#"update"#,
    r#"update.Categories"#,
    r#"update.Identity.RevisionNumber"#,
    r#"update.Identity.UpdateID"#,
    r#"update.InstallationBehavior.RebootBehavior"#,
    r#"update.IsHidden"#,
    r#"update.IsMandatory"#,
    r#"update.KBArticleIDs"#,
    r#"update.MsrcSeverity"#,
    r#"update.Title"#,
    r#"updates"#,
    r#"updates"#,
    r#"x4"#,
];


pub const WUA_PUNCTUATION: &str = "\n \"$'(),:;=@[]{|}";


pub fn words(script: &str) -> Vec<&str> {
    let mut found: Vec<&str> = script
        .split(|character: char| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '\\' | '-')))
        .filter(|word| !word.is_empty())
        .collect();
    found.sort_unstable();
    found
}


pub fn punctuation(script: &str) -> String {
    let mut found: Vec<char> = script
        .chars()
        .filter(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '\\' | '-')))
        .collect();
    found.sort_unstable();
    found.dedup();
    found.into_iter().collect()
}


pub fn is_allowed(script: &str, expected_words: &[&str], expected_punctuation: &str) -> bool {
    words(script) == expected_words && punctuation(script) == expected_punctuation
}


pub fn first_lines_are_pins(script: &str, module_path: &str) -> bool {
    let mut lines = script.lines();
    lines.next() == Some(r"$env:Path = 'C:\Windows\System32'") && lines.next() == Some(module_path)
}


const WUA_MODULE_PATH: &str = r"$env:PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'";


#[test]
fn the_search_script_holds_exactly_the_allowed_words_and_punctuation_and_pins_the_environment() -> TestResult {
    assert!(is_allowed(WUA_SEARCH_SCRIPT, &WUA_TOKENS, WUA_PUNCTUATION));
    assert!(first_lines_are_pins(WUA_SEARCH_SCRIPT, WUA_MODULE_PATH));
    Ok(())
}


#[test]
fn a_changed_pin_line_is_detected() -> TestResult {
    assert!(!first_lines_are_pins(
        &WUA_SEARCH_SCRIPT.replacen("Modules'", "Modulez'", 1),
        WUA_MODULE_PATH
    ));
    Ok(())
}


const SEARCH_MUTANTS: [(&str, &str); 10] = [
    (r"Microsoft.PowerShell.Core\ForEach-Object", "ForEach-Object"),
    (r"Microsoft.PowerShell.Core\ForEach-Object", "%"),
    (r"Microsoft.PowerShell.Core\ForEach-Object", "foreach-object"),
    (r"Microsoft.PowerShell.Utility\New-Object System.Text", r"Evil\New-Object System.Text"),
    (r"Microsoft.PowerShell.Utility\New-Object System.Text", "& ('New-'+'Object') System.Text"),
    (r"Microsoft.PowerShell.Utility\Remove-TypeData System.Array", r". .\evil.ps1"),
    (r"Microsoft.PowerShell.Utility\Remove-TypeData System.Array", "Invoke-Evil System.Array"),
    (
        r"Microsoft.PowerShell.Utility\ConvertTo-Json",
        "microsoft.powershell.utility\\convertto-json",
    ),
    (r"Microsoft.PowerShell.Utility\ConvertTo-Json", "ConvertTo-Json"),
    ("$_.CategoryID", "$_.CategoryID | ?"),
];


#[test]
fn every_mutant_of_the_search_script_is_refused() -> TestResult {
    SEARCH_MUTANTS.iter().try_for_each(|(from, to)| {
        assert!(WUA_SEARCH_SCRIPT.contains(from), "{from}");
        let mutant = WUA_SEARCH_SCRIPT.replacen(from, to, 1);
        assert!(!is_allowed(&mutant, &WUA_TOKENS, WUA_PUNCTUATION), "{to}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn an_extra_allowed_command_call_is_refused() -> TestResult {
    let search = format!("{WUA_SEARCH_SCRIPT}Microsoft.PowerShell.Utility\\New-Object System.Text.UTF8Encoding\n");
    assert!(!is_allowed(&search, &WUA_TOKENS, WUA_PUNCTUATION));
    Ok(())
}
