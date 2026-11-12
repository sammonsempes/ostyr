use crate::alerts::{alerts_list, alerts_show, escape_json, printable};
use crate::cases::{cases_list, cases_show};
use crate::commands::{apply_command, audit_verify, config_validate, login, logout, plan_command, whoami};
use crate::error::CliError;
use crate::model::{AlertsCommand, AuditCommand, CasesCommand, Cli, Command, ConfigCommand, Context, OutputFormat, Report};
use crate::session::session_path;
use crate::types::SendFn;
use clap::Parser;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;


pub const USAGE_EXIT_CODE: u8 = 2;


/// Runs the parsed command; `prompt` receives the confirmation question of `apply`.
pub fn execute(
    cli: &Cli,
    default_config_dir: Option<PathBuf>,
    send: &SendFn,
    input: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> Result<Report, CliError> {
    let config_dir = cli.config_dir.clone().or(default_config_dir).ok_or(CliError::NoConfigDir)?;
    let ctx = Context {
        server: cli.server.as_deref(),
        ca_file: cli.ca_file.as_deref(),
        session_file: session_path(&config_dir),
        send,
    };
    match &cli.command {
        Command::Login { username, totp_code } => login(&ctx, username, totp_code.as_deref(), input),
        Command::Logout => logout(&ctx),
        Command::Whoami => whoami(&ctx),
        Command::Config {
            action: ConfigCommand::Validate { dir },
        } => config_validate(dir),
        Command::Plan { desired, state } => plan_command(desired, state),
        Command::Apply(args) => apply_command(&ctx, args, input, prompt),
        Command::Audit {
            action: AuditCommand::Verify { file },
        } => audit_verify(file),
        Command::Alerts {
            action: AlertsCommand::List { limit, cursor },
        } => alerts_list(&ctx, *limit, cursor.as_deref()),
        Command::Alerts {
            action: AlertsCommand::Show { id },
        } => alerts_show(&ctx, id),
        Command::Cases {
            action: CasesCommand::List { limit, cursor },
        } => cases_list(&ctx, *limit, cursor.as_deref()),
        Command::Cases {
            action: CasesCommand::Show { id },
        } => cases_show(&ctx, id),
    }
}


pub fn render(format: OutputFormat, report: &Report, out: &mut dyn Write) -> Result<(), CliError> {
    match format {
        OutputFormat::Text => writeln!(out, "{}", report.text).map_err(CliError::from),
        OutputFormat::Json => {
            let line = escape_json(&serde_json::to_string(&report.json)?);
            writeln!(out, "{line}").map_err(CliError::from)
        }
    }
}


pub fn render_error(format: OutputFormat, error: &CliError, err: &mut dyn Write) -> io::Result<()> {
    match format {
        OutputFormat::Text => writeln!(err, "error: {}", printable(&error.to_string())),
        OutputFormat::Json => writeln!(err, "{}", escape_json(&json!({ "error": error.to_string() }).to_string())),
    }
}


/// Parses the arguments, runs the command and maps the outcome to an exit code: results on `out`, errors and prompts on `err`.
pub fn run_reporting(
    args: &[String],
    default_config_dir: Option<PathBuf>,
    send: &SendFn,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<ExitCode> {
    match Cli::try_parse_from(args) {
        Ok(cli) => match execute(&cli, default_config_dir, send, input, err).and_then(|report| render(cli.output, &report, out)) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(error) => render_error(cli.output, &error, err).map(|()| ExitCode::FAILURE),
        },
        Err(usage) if usage.use_stderr() => write!(err, "{usage}").map(|()| ExitCode::from(USAGE_EXIT_CODE)),
        Err(informative) => write!(out, "{informative}").map(|()| ExitCode::SUCCESS),
    }
}
