use crate::types::SendFn;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};


#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}


#[derive(Parser)]
#[command(name = "xdrctl", about = "Command line client of the XDR platform API")]
pub struct Cli {
    /// Base address of the API, https only; defaults to the one stored by `login`.
    #[arg(long, global = true)]
    pub server: Option<String>,
    /// PEM file with the certificate authority that signed the server certificate.
    #[arg(long, global = true)]
    pub ca_file: Option<PathBuf>,
    /// Directory holding the session file; defaults to the user configuration directory.
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub output: OutputFormat,
    #[command(subcommand)]
    pub command: Command,
}


#[derive(Subcommand)]
pub enum Command {
    /// Logs in; the password is read from the first line of standard input.
    Login {
        #[arg(long)]
        username: String,
        #[arg(long)]
        totp_code: Option<String>,
    },
    Logout,
    Whoami,
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
    /// Shows what applying `desired` would change in `state`.
    Plan {
        desired: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    /// Applies `desired` to `state`, audited under the logged-in account.
    Apply(ApplyArgs),
    Audit {
        #[command(subcommand)]
        action: AuditCommand,
    },
    Alerts {
        #[command(subcommand)]
        action: AlertsCommand,
    },
    Cases {
        #[command(subcommand)]
        action: CasesCommand,
    },
}


#[derive(Args)]
pub struct ApplyArgs {
    pub desired: PathBuf,
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long)]
    pub audit_file: PathBuf,
    #[arg(long)]
    pub justification: String,
    #[arg(long)]
    pub yes: bool,
}


#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Validates `platform.yaml` as a platform file and every other `.yaml` or `.yml` file as a module configuration.
    Validate { dir: PathBuf },
}


#[derive(Subcommand)]
pub enum AuditCommand {
    Verify { file: PathBuf },
}


#[derive(Subcommand)]
pub enum AlertsCommand {
    /// Lists alerts, newest first; the next cursor is printed when there are more.
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Shows one alert by id.
    Show { id: String },
}


#[derive(Subcommand)]
pub enum CasesCommand {
    /// Lists cases, newest first; the next cursor is printed when there are more.
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Shows one case by id.
    Show { id: String },
}


#[derive(Deserialize)]
pub struct CaseCountsView {
    pub tasks: u64,
    pub observables: u64,
    pub comments: u64,
    pub history: u64,
    pub alerts: u64,
}


#[derive(Deserialize)]
pub struct CaseSummaryView {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub assignee: Option<String>,
    pub case_type: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: i64,
    pub counts: CaseCountsView,
}


#[derive(Deserialize)]
pub struct CaseTaskView {
    pub title: String,
    pub status: String,
}


#[derive(Deserialize)]
pub struct CaseDetailView {
    #[serde(flatten)]
    pub summary: CaseSummaryView,
    pub description: Option<String>,
    pub resolution: Option<String>,
    pub template: Option<String>,
    pub tasks: Vec<CaseTaskView>,
}


#[derive(Deserialize)]
pub struct CasePageView {
    pub items: Vec<CaseSummaryView>,
    pub next_cursor: Option<String>,
}


#[derive(Deserialize)]
pub struct AlertView {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: String,
    pub event_time: String,
    pub created: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub event_ids: Vec<String>,
    pub summary: serde_json::Value,
    pub summary_truncated: bool,
}


#[derive(Deserialize)]
pub struct AlertPage {
    pub items: Vec<AlertView>,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub token: Option<String>,
    pub body: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
}


#[derive(Serialize, Deserialize)]
pub struct Session {
    pub server: String,
    pub token: String,
}


#[derive(Deserialize)]
pub struct LoginReply {
    pub token: String,
}


#[derive(Debug, Deserialize)]
pub struct MeReply {
    pub username: String,
    pub roles: Vec<String>,
    pub mfa_enrolled: bool,
}


#[derive(Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}


#[derive(Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}


#[derive(Serialize)]
pub struct LoginBody<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub totp_code: Option<&'a str>,
}


pub struct Report {
    pub text: String,
    pub json: serde_json::Value,
}


pub struct Context<'a> {
    pub server: Option<&'a str>,
    pub ca_file: Option<&'a Path>,
    pub session_file: PathBuf,
    pub send: &'a SendFn<'a>,
}
