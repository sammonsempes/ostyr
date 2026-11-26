use crate::types::TestResult;
use sys_windows::console::CUT_MARKER;
use sys_windows::job_command::{
    command_line_text, job_launch, process_ids_from, quote_argument, MAX_COMMAND_LINE_UNITS, MAX_ENVIRONMENT_UNITS, MAX_JOB_ARGUMENTS,
    MAX_JOB_ENVIRONMENT,
};
use sys_windows::types::ConsoleError;


const PROGRAM: &str = "C:\\Windows\\System32\\winget.exe";


const DIRECTORY: &str = "C:\\Windows\\System32";


const HIGH_WORD: u64 = 0x0000_0002_0000_0005;


const LINE_FITS_MARGIN: usize = 4;


const LINE_OVER_MARGIN: usize = 3;


const BLOCK_TERMINATORS: usize = 2;


const ID_A: u32 = 10;


const ID_B: u32 = 20;


const BIG_ID: u64 = 0x1_0000_0001;


fn decode(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}


#[test]
fn quoting_follows_the_argv_rules() -> TestResult {
    assert_eq!(quote_argument("plain"), "plain");
    assert_eq!(quote_argument(""), "\"\"");
    assert_eq!(quote_argument("a b"), "\"a b\"");
    assert_eq!(quote_argument("tab\there"), "\"tab\there\"");
    assert_eq!(quote_argument("say \"hi\""), "\"say \\\"hi\\\"\"");
    assert_eq!(quote_argument("dir \\"), "\"dir \\\\\"");
    assert_eq!(quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
    assert_eq!(quote_argument("a\\b c"), "\"a\\b c\"");
    assert_eq!(quote_argument("\""), "\"\\\"\"");
    Ok(())
}


#[test]
fn a_launch_holds_every_piece_nul_terminated() -> TestResult {
    let launch = job_launch(PROGRAM, &["upgrade", "--source", "my source"], &[("PATH", "C:\\x")], DIRECTORY)?;
    assert_eq!(decode(&launch.program), format!("{PROGRAM}\0"));
    assert_eq!(decode(&launch.command), format!("\"{PROGRAM}\" upgrade --source \"my source\"\0"));
    assert_eq!(decode(&launch.environment), "PATH=C:\\x\0\0");
    assert_eq!(decode(&launch.directory), format!("{DIRECTORY}\0"));
    Ok(())
}


#[test]
fn an_empty_environment_is_an_empty_block_not_an_inherited_one() -> TestResult {
    let launch = job_launch(PROGRAM, &[], &[], DIRECTORY)?;
    assert_eq!(launch.environment, vec![0, 0]);
    Ok(())
}


#[test]
fn programs_outside_the_grammar_are_refused_by_name() -> TestResult {
    for program in [
        "winget.exe",
        "C:winget.exe",
        "\\\\server\\share\\a.exe",
        "C:\\a\\..\\b.exe",
        "C:\\a/b.exe",
        "C:\\a\"b.exe",
        "C:\\Windows\\System32\\setup.bat",
        "C:\\Windows\\System32\\setup.cmd",
        "C:\\Windows\\System32",
        "C:\\a;b.exe",
    ] {
        assert!(
            matches!(job_launch(program, &[], &[], DIRECTORY), Err(ConsoleError::BadProgram(_))),
            "{program}"
        );
    }
    assert!(job_launch("C:\\Windows\\System32\\CMD.EXE", &[], &[], DIRECTORY).is_ok());
    Ok(())
}


#[test]
fn a_long_refused_program_is_cut_in_the_error() -> TestResult {
    let long = format!("C:\\{}", "a".repeat(MAX_COMMAND_LINE_UNITS));
    let text = job_launch(&long, &[], &[], DIRECTORY).err().ok_or("accepted")?.to_string();
    assert!(text.contains(CUT_MARKER));
    assert!(text.len() < long.len());
    Ok(())
}


#[test]
fn directories_outside_the_grammar_are_refused_by_name() -> TestResult {
    for directory in ["", "relative", "C:", "\\\\?\\C:\\x", "C:\\a\\..", "C:\\a;b", "C:\\a\"b"] {
        assert!(
            matches!(job_launch(PROGRAM, &[], &[], directory), Err(ConsoleError::BadDirectory(_))),
            "{directory}"
        );
    }
    Ok(())
}


#[test]
fn an_argument_with_a_nul_is_refused_by_index_without_its_text() -> TestResult {
    let refused = job_launch(PROGRAM, &["ok", "sec\0ret"], &[], DIRECTORY).err().ok_or("accepted")?;
    assert!(matches!(refused, ConsoleError::BadArgument { index: 1 }));
    assert!(!format!("{refused} {refused:?}").contains("sec"));
    Ok(())
}


#[test]
fn counts_are_bounded_before_anything_is_built() -> TestResult {
    let many = vec!["x"; MAX_JOB_ARGUMENTS + 1];
    assert!(matches!(
        job_launch(PROGRAM, &many, &[], DIRECTORY),
        Err(ConsoleError::TooMany { what: "arguments", .. })
    ));
    assert!(job_launch(PROGRAM, &many.iter().skip(1).copied().collect::<Vec<_>>(), &[], DIRECTORY).is_ok());
    let names = (0..=MAX_JOB_ENVIRONMENT).map(|index| format!("V{index}")).collect::<Vec<_>>();
    let entries = names.iter().map(|name| (name.as_str(), "1")).collect::<Vec<_>>();
    assert!(matches!(
        job_launch(PROGRAM, &[], &entries, DIRECTORY),
        Err(ConsoleError::TooMany {
            what: "environment entries",
            ..
        })
    ));
    assert!(job_launch(PROGRAM, &[], &entries.iter().skip(1).copied().collect::<Vec<_>>(), DIRECTORY).is_ok());
    Ok(())
}


#[test]
fn a_command_line_is_bounded_in_utf16_units() -> TestResult {
    let fits = "a".repeat(MAX_COMMAND_LINE_UNITS - PROGRAM.len() - LINE_FITS_MARGIN);
    assert!(command_line_text(PROGRAM, &[fits.as_str()]).is_ok());
    let over = "a".repeat(MAX_COMMAND_LINE_UNITS - PROGRAM.len() - LINE_OVER_MARGIN);
    assert!(matches!(
        command_line_text(PROGRAM, &[over.as_str()]),
        Err(ConsoleError::TooLarge { what: "command line", .. })
    ));
    Ok(())
}


#[test]
fn an_environment_block_is_bounded_in_utf16_units() -> TestResult {
    let value = "v".repeat(MAX_ENVIRONMENT_UNITS);
    assert!(matches!(
        job_launch(PROGRAM, &[], &[("BIG", value.as_str())], DIRECTORY),
        Err(ConsoleError::TooLarge {
            what: "environment block",
            ..
        })
    ));
    let fits = "v".repeat(MAX_ENVIRONMENT_UNITS - "BIG=".len() - BLOCK_TERMINATORS);
    assert!(job_launch(PROGRAM, &[], &[("BIG", fits.as_str())], DIRECTORY).is_ok());
    Ok(())
}


#[test]
fn environment_errors_pass_through() -> TestResult {
    assert!(matches!(
        job_launch(PROGRAM, &[], &[("A B", "1")], DIRECTORY),
        Err(ConsoleError::BadEnvironmentName)
    ));
    assert!(matches!(
        job_launch(PROGRAM, &[], &[("A", "1"), ("a", "2")], DIRECTORY),
        Err(ConsoleError::DuplicateEnvironmentName { .. })
    ));
    Ok(())
}


#[test]
fn the_process_list_is_read_from_its_header_and_cut_to_the_buffer() -> TestResult {
    assert!(process_ids_from(&[]).is_empty());
    assert_eq!(process_ids_from(&[HIGH_WORD, u64::from(ID_A), u64::from(ID_B)]), vec![ID_A, ID_B]);
    assert_eq!(process_ids_from(&[HIGH_WORD, u64::from(ID_A)]), vec![ID_A]);
    assert_eq!(process_ids_from(&[HIGH_WORD, BIG_ID, u64::from(ID_B)]), vec![ID_B]);
    assert!(process_ids_from(&[1, u64::from(ID_A)]).is_empty());
    Ok(())
}
