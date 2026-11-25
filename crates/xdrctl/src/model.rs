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
    Assets {
        #[command(subcommand)]
        action: AssetsCommand,
    },
    Risk {
        #[command(subcommand)]
        action: RiskCommand,
    },
    Vulns {
        #[command(subcommand)]
        action: VulnsCommand,
    },
    Grc {
        #[command(subcommand)]
        action: GrcCommand,
    },
    AttackPaths {
        #[command(subcommand)]
        action: AttackPathsCommand,
    },
}


#[derive(Subcommand)]
pub enum GrcCommand {
    /// Lists the newest stored compliance reports (there is no cursor).
    List {
        #[arg(long)]
        framework: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
    },
    /// Shows the summary of one stored compliance report.
    Show { id: String },
}


#[derive(Subcommand)]
pub enum AttackPathsCommand {
    /// Lists the newest stored attack-path reports (there is no cursor).
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
    },
    /// Shows the summary of one stored attack-path report.
    Show { id: String },
}


#[derive(Deserialize)]
pub struct GrcItemView {
    pub id: i64,
    pub framework: String,
    pub version: u32,
    pub generated: String,
    pub digest: String,
    pub bytes: u64,
    pub stored_at: i64,
}


#[derive(Deserialize)]
pub struct GrcListReply {
    pub items: Vec<GrcItemView>,
}


#[derive(Deserialize)]
pub struct GrcCountsView {
    pub compliant: u64,
    pub partially_compliant: u64,
    pub non_compliant: u64,
    pub not_assessable: u64,
}


#[derive(Deserialize)]
pub struct GrcBodyView {
    pub framework: String,
    pub version: u32,
    pub generated: String,
    pub counts: GrcCountsView,
    pub controls: Vec<serde::de::IgnoredAny>,
    pub gaps: Vec<serde::de::IgnoredAny>,
    pub plan: Vec<serde::de::IgnoredAny>,
}


#[derive(Deserialize)]
pub struct AttackItemView {
    pub id: i64,
    pub graph_digest: String,
    pub generated: String,
    pub digest: String,
    pub bytes: u64,
    pub truncated: bool,
    pub budget_reached: bool,
    pub unsearched_count: u64,
    pub stored_at: i64,
}


#[derive(Deserialize)]
pub struct AttackListReply {
    pub items: Vec<AttackItemView>,
}


#[derive(Deserialize)]
pub struct AttackBodyView {
    pub graph_digest: String,
    pub truncated: bool,
    pub budget_reached: bool,
    pub unsearched: Vec<serde::de::IgnoredAny>,
    pub paths: Vec<serde::de::IgnoredAny>,
    pub choke_points: Vec<serde::de::IgnoredAny>,
    pub recommendations: Vec<serde::de::IgnoredAny>,
}


#[derive(Subcommand)]
pub enum VulnsCommand {
    /// Lists the open vulnerability findings, highest priority first; the next cursor is printed when there are more.
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=500))]
        limit: Option<u32>,
        /// The printed text form of the cursor (percent-encoded), exactly as the previous page showed it.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Shows the findings of one asset.
    Show { asset: String },
}


#[derive(Deserialize)]
pub struct FindingView {
    pub asset: String,
    pub ecosystem: String,
    pub package: String,
    pub record_id: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub cvss: f64,
    pub epss: f64,
    pub kev: bool,
    pub priority: u32,
    pub first_seen: String,
    pub last_seen: String,
}


#[derive(Deserialize)]
pub struct FindingsListReply {
    pub items: Vec<FindingView>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}


#[derive(Deserialize)]
pub struct FindingsAssetReply {
    pub items: Vec<FindingView>,
    pub skipped: usize,
    pub truncated: bool,
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
    /// Lists the deduplicated alert groups of the tenant.
    Groups,
}


#[derive(Subcommand)]
pub enum AssetsCommand {
    /// Lists assets ordered by id; the next cursor is printed when there are more.
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Shows one asset by id.
    Show { id: String },
}


#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RiskKind {
    Host,
    User,
}


#[derive(Subcommand)]
pub enum RiskCommand {
    /// Lists the riskiest hosts and users of the tenant, highest first.
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=500))]
        limit: Option<u32>,
        #[arg(long, value_enum)]
        kind: Option<RiskKind>,
    },
    /// Shows the risk score of one host or user.
    Show {
        #[arg(value_enum)]
        kind: RiskKind,
        id: String,
    },
}


#[derive(Deserialize)]
pub struct RiskEntityRow {
    pub kind: String,
    pub id: String,
    pub value: u64,
    pub contributions_used: u64,
    pub contributions_dropped: u64,
}


#[derive(Deserialize)]
pub struct RiskTruncatedView {
    pub limit: String,
    pub read: u64,
    pub cap: u64,
}


#[derive(Deserialize)]
pub struct RiskListReply {
    pub computed_at: i64,
    pub alerts_read: u64,
    pub informational: u64,
    pub refused: std::collections::BTreeMap<String, u64>,
    pub truncated: Option<RiskTruncatedView>,
    pub entities: Vec<RiskEntityRow>,
}


#[derive(Deserialize)]
pub struct RiskShowReply {
    pub computed_at: i64,
    pub truncated: Option<RiskTruncatedView>,
    pub entity: RiskEntityRow,
}


#[derive(Deserialize)]
pub struct AssetCountsView {
    pub keys: u64,
    pub attributes: u64,
    pub open_conflicts: u64,
}


#[derive(Deserialize)]
pub struct AssetSummaryView {
    pub id: String,
    pub kind: String,
    pub lifecycle: String,
    pub version: u64,
    pub counts: AssetCountsView,
}


#[derive(Deserialize)]
pub struct AssetKeyView {
    pub key: String,
    pub value: String,
}


#[derive(Deserialize)]
pub struct AssetAttributeView {
    pub name: String,
    pub value: String,
    pub source: String,
}


#[derive(Deserialize)]
pub struct AssetDetailView {
    #[serde(flatten)]
    pub summary: AssetSummaryView,
    pub keys: Vec<AssetKeyView>,
    pub attributes: Vec<AssetAttributeView>,
    pub truncated: bool,
}


#[derive(Deserialize)]
pub struct AssetPageView {
    pub items: Vec<AssetSummaryView>,
    pub next_cursor: Option<String>,
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


#[derive(Deserialize)]
pub struct GroupRow {
    pub rule_id: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub alert_count: u64,
    pub duplicates: u64,
    pub max_severity: String,
    pub first_time: String,
    pub last_time: String,
    pub omitted: bool,
    pub cut_at_older: bool,
}


#[derive(Deserialize)]
pub struct GroupsReply {
    pub groups: Vec<GroupRow>,
    pub complete: bool,
    pub alerts_read: u64,
    pub oldest_read: Option<String>,
}
