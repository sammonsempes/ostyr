use crate::console::{drive_root, environment_block, shown_text, wide_null};
use crate::types::{ConsoleError, JobLaunch};


pub const MAX_JOB_ARGUMENTS: usize = 64;


pub const MAX_JOB_ENVIRONMENT: usize = 128;


pub const MAX_COMMAND_LINE_UNITS: usize = 32_767;


pub const MAX_ENVIRONMENT_UNITS: usize = 32_767;


pub const PROGRAM_EXTENSION: &str = ".exe";


/// One argument as `CommandLineToArgvW` reads it back: quoted when empty or holding a blank or a quote, backslashes before a quote doubled.
pub fn quote_argument(argument: &str) -> String {
    let plain = !argument.is_empty() && !argument.contains([' ', '\t', '\n', '\u{b}', '"']);
    if plain {
        argument.to_string()
    } else {
        let (body, trailing) = argument
            .chars()
            .fold((String::from('"'), 0), |(mut quoted, backslashes), character| match character {
                '\\' => {
                    quoted.push('\\');
                    (quoted, backslashes + 1)
                }
                '"' => {
                    quoted.extend(std::iter::repeat_n('\\', backslashes + 1));
                    quoted.push('"');
                    (quoted, 0)
                }
                other => {
                    quoted.push(other);
                    (quoted, 0)
                }
            });
        let closing = std::iter::repeat_n('\\', trailing).chain(std::iter::once('"')).collect::<String>();
        format!("{body}{closing}")
    }
}


/// The process ids of a `JobObjectBasicProcessIdList` answer as 64-bit words: word 0 holds both counts, the listed one high, the ids follow.
pub fn process_ids_from(words: &[u64]) -> Vec<u32> {
    let listed = words.first().map_or(0, |header| header >> u32::BITS);
    let count = usize::try_from(listed).unwrap_or(usize::MAX);
    words.iter().skip(1).take(count).filter_map(|word| u32::try_from(*word).ok()).collect()
}


fn check_program(program: &str) -> Result<(), ConsoleError> {
    let executable = program.to_ascii_lowercase().ends_with(PROGRAM_EXTENSION);
    if executable && drive_root(program).is_some() {
        Ok(())
    } else {
        Err(ConsoleError::BadProgram(shown_text(program)))
    }
}


fn check_directory(directory: &str) -> Result<(), ConsoleError> {
    drive_root(directory)
        .map(|_| ())
        .ok_or_else(|| ConsoleError::BadDirectory(shown_text(directory)))
}


fn check_counts(arguments: usize, environment: usize) -> Result<(), ConsoleError> {
    if arguments > MAX_JOB_ARGUMENTS {
        Err(ConsoleError::TooMany {
            what: "arguments",
            max: MAX_JOB_ARGUMENTS,
        })
    } else if environment > MAX_JOB_ENVIRONMENT {
        Err(ConsoleError::TooMany {
            what: "environment entries",
            max: MAX_JOB_ENVIRONMENT,
        })
    } else {
        Ok(())
    }
}


/// The command line: the quoted program, then each argument quoted; an argument with a NUL or a line past `MAX_COMMAND_LINE_UNITS` is refused.
pub fn command_line_text(program: &str, arguments: &[&str]) -> Result<String, ConsoleError> {
    arguments.iter().enumerate().try_for_each(|(index, argument)| {
        if argument.contains('\0') {
            Err(ConsoleError::BadArgument { index })
        } else {
            Ok(())
        }
    })?;
    let line = std::iter::once(format!("\"{program}\""))
        .chain(arguments.iter().map(|argument| quote_argument(argument)))
        .collect::<Vec<_>>()
        .join(" ");
    if line.encode_utf16().count() >= MAX_COMMAND_LINE_UNITS {
        Err(ConsoleError::TooLarge {
            what: "command line",
            max_units: MAX_COMMAND_LINE_UNITS,
        })
    } else {
        Ok(line)
    }
}


/// Every piece of a job spawn, checked: an absolute local `.exe` path, an absolute directory, bounded arguments and an explicit environment (nothing inherited).
pub fn job_launch(program: &str, arguments: &[&str], environment: &[(&str, &str)], directory: &str) -> Result<JobLaunch, ConsoleError> {
    check_program(program)?;
    check_directory(directory)?;
    check_counts(arguments.len(), environment.len())?;
    let command = command_line_text(program, arguments)?;
    let block = environment_block(environment)?;
    if block.len() > MAX_ENVIRONMENT_UNITS {
        Err(ConsoleError::TooLarge {
            what: "environment block",
            max_units: MAX_ENVIRONMENT_UNITS,
        })
    } else {
        Ok(JobLaunch {
            program: wide_null(program),
            command: wide_null(&command),
            environment: block,
            directory: wide_null(directory),
        })
    }
}
