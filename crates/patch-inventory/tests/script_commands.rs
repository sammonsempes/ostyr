#[path = "common/types.rs"]
mod types;


use patch_inventory::winget_script::WINGET_SCRIPT;
use patch_inventory::wua_script::WUA_SEARCH_SCRIPT;
use types::TestResult;


const MIN_SEARCH_COMMANDS: usize = 5;


const MIN_WINGET_COMMANDS: usize = 6;


pub fn is_command_name(token: &str) -> bool {
    let name = token.rsplit('\\').next().unwrap_or("");
    name.split_once('-').is_some_and(|(verb, noun)| {
        verb.starts_with(|first: char| first.is_ascii_uppercase())
            && verb.chars().all(|character| character.is_ascii_alphabetic())
            && noun.starts_with(|first: char| first.is_ascii_uppercase())
    })
}


pub fn command_tokens(script: &str) -> Vec<&str> {
    script
        .split(|character: char| !(character.is_ascii_alphanumeric() || matches!(character, '.' | '\\' | '-')))
        .filter(|token| is_command_name(token))
        .collect()
}


pub fn bare_commands(script: &str) -> Vec<&str> {
    command_tokens(script)
        .into_iter()
        .filter(|token| token.split_once('\\').is_none_or(|(module, _)| module.is_empty()))
        .collect()
}


#[test]
fn every_command_in_the_search_script_is_module_qualified_and_the_environment_is_pinned() -> TestResult {
    assert!(bare_commands(WUA_SEARCH_SCRIPT).is_empty(), "{:?}", bare_commands(WUA_SEARCH_SCRIPT));
    assert!(command_tokens(WUA_SEARCH_SCRIPT).len() >= MIN_SEARCH_COMMANDS);
    let mut lines = WUA_SEARCH_SCRIPT.lines();
    assert_eq!(lines.next(), Some(r"$env:Path = 'C:\Windows\System32'"));
    assert_eq!(
        lines.next(),
        Some(r"$env:PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'")
    );
    Ok(())
}


#[test]
fn a_bare_command_in_the_search_script_is_detected_by_the_tokeniser() -> TestResult {
    [
        (r"Microsoft.PowerShell.Core\ForEach-Object", "ForEach-Object"),
        (r"Microsoft.PowerShell.Utility\New-Object", "New-Object"),
        (r"Microsoft.PowerShell.Utility\Remove-TypeData", "Remove-TypeData"),
        (r"Microsoft.PowerShell.Utility\ConvertTo-Json", "ConvertTo-Json"),
    ]
    .iter()
    .try_for_each(|(qualified, bare)| {
        let mutant = WUA_SEARCH_SCRIPT.replacen(qualified, bare, 1);
        assert_eq!(bare_commands(&mutant), [*bare]);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn every_command_in_the_script_is_module_qualified_and_the_environment_is_pinned() -> TestResult {
    assert!(bare_commands(WINGET_SCRIPT).is_empty(), "{:?}", bare_commands(WINGET_SCRIPT));
    assert!(command_tokens(WINGET_SCRIPT).len() >= MIN_WINGET_COMMANDS);
    let mut lines = WINGET_SCRIPT.lines();
    assert_eq!(lines.next(), Some(r"$env:Path = 'C:\Windows\System32'"));
    let modules = lines.next().ok_or("no second line")?;
    assert!(modules.starts_with(r"$env:PSModulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules;"));
    assert!(modules.ends_with(r"C:\Program Files\WindowsPowerShell\Modules'"));
    Ok(())
}


#[test]
fn a_bare_command_is_detected_by_the_tokeniser() -> TestResult {
    [
        (r"Microsoft.PowerShell.Core\Where-Object", "Where-Object"),
        (r"Microsoft.PowerShell.Core\Import-Module", "Import-Module"),
        (r"Microsoft.WinGet.Client\Get-WinGetPackage", "Get-WinGetPackage"),
        (r"Microsoft.PowerShell.Utility\ConvertTo-Json", "ConvertTo-Json"),
    ]
    .iter()
    .try_for_each(|(qualified, bare)| {
        let mutant = WINGET_SCRIPT.replacen(qualified, bare, 1);
        assert_eq!(bare_commands(&mutant), [*bare]);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
