use ai_gateway::chat::{chat, production_deps};
use ai_gateway::settings::{validate_ai, AiSettings};
use core_config::load::load_file;
use std::error::Error;
use std::fs;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;


fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [settings, instructions, data] => call(settings, instructions, data),
        _ => Err("usage: ai_chat <ai.yaml> <instructions-file> <data.json>".into()),
    }
}


fn call(settings_path: &str, instructions_path: &str, data_path: &str) -> Result<(), Box<dyn Error>> {
    let settings: AiSettings = load_file(Path::new(settings_path))?;
    validate_ai(&settings)?;
    let instructions = fs::read_to_string(instructions_path)?;
    let data: serde_json::Value = serde_json::from_str(&fs::read_to_string(data_path)?)?;
    let answer = chat(&settings, &instructions, &data, &production_deps())?;
    let mut out = stdout();
    writeln!(out, "content {:?}", answer.content)?;
    writeln!(out, "prompt_tokens {:?}", answer.prompt_tokens)?;
    writeln!(out, "completion_tokens {:?}", answer.completion_tokens)?;
    writeln!(out, "finish_reason {:?}", answer.finish_reason)?;
    Ok(())
}


fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let reported = writeln!(stderr(), "{error}");
            reported.map_or(ExitCode::FAILURE, |()| ExitCode::FAILURE)
        }
    }
}
