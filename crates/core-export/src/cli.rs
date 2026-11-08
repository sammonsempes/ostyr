use crate::config::{load_export, ExportConfig, OtlpConfig, SyslogConfig, SyslogTransport, WebhookConfig};
use crate::ecs::{blank_event, to_json, EcsEvent, EventFields, HostFields};
use crate::error::ExportError;
use crate::http::{build_agent, build_agent_with, post_json, post_otlp};
use crate::otlp::prepare_otlp;
use crate::pipeline::{export_otlp, export_webhook, ExportReport};
use crate::reload::open_export_engine;
use crate::syslog::{format_message, send_datagrams, write_frames, SyslogHeader};
use crate::tls::{client_config, close, open_stream};
use crate::types::{ResolveFn, SleepFn};
use crate::webhook::RetryPolicy;
use core_audit::log::{append, open_file_log, AuditLog};
use core_config::reload::{current_config, ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::thread::sleep;
use time::OffsetDateTime;


pub const NO_REDIRECTS: u32 = 0;


pub const SAMPLE_HOST: &str = "export-demo";


pub const SAMPLE_DATASET: &str = "ostyr.demo";


pub const SAMPLE_SEVERITY: u32 = 1;


pub const AUDIT_EXTENSION: &str = "audit";


pub const AUDIT_MODULE: &str = "core-export";


pub const AUDIT_REQUEST_ID: &str = "export-reload";


pub fn sample_event(sequence: u64, now: OffsetDateTime) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_string()),
            dataset: Some(SAMPLE_DATASET.to_string()),
            severity: Some(SAMPLE_SEVERITY),
            sequence: Some(sequence),
            ..EventFields::default()
        },
        message: Some(format!("sample event {sequence}")),
        host: Some(HostFields {
            name: Some(SAMPLE_HOST.to_string()),
            ..HostFields::default()
        }),
        ..blank_event(now)
    }
}


pub fn sample_events(count: u64, first_sequence: u64, now: OffsetDateTime) -> Vec<EcsEvent> {
    (first_sequence..first_sequence.saturating_add(count))
        .map(|sequence| sample_event(sequence, now))
        .collect()
}


fn read_ca(ca_file: Option<&String>) -> Result<Option<Vec<u8>>, ExportError> {
    ca_file
        .map(|path| {
            fs::read(path).map_err(|source| ExportError::Io {
                context: format!("read CA {path}"),
                source,
            })
        })
        .transpose()
}


pub fn run_webhook(
    config: &WebhookConfig,
    events: &[EcsEvent],
    resolve: &ResolveFn,
    policy: &RetryPolicy,
    pause: &mut SleepFn,
    now: OffsetDateTime,
) -> Result<ExportReport, ExportError> {
    let ca = read_ca(config.ca_file.as_ref())?;
    let agent = build_agent(ca.as_deref())?;
    let token = config.token.as_ref().map(resolve).transpose().map_err(ExportError::Secret)?;
    let mut post = |body: &str| post_json(&agent, &config.url, token.as_deref(), body);
    export_webhook(events, config, policy, &mut post, pause, SAMPLE_HOST, now)
}


pub fn run_otlp(
    config: &OtlpConfig,
    events: &[EcsEvent],
    policy: &RetryPolicy,
    pause: &mut SleepFn,
    now: OffsetDateTime,
) -> Result<ExportReport, ExportError> {
    let token = prepare_otlp(config)?;
    let ca = read_ca(config.ca_file.as_ref())?;
    let agent = build_agent_with(ca.as_deref(), NO_REDIRECTS)?;
    let mut post = |body: &str| post_otlp(&agent, &config.endpoint, token.as_deref(), body);
    export_otlp(events, config, policy, &mut post, pause, SAMPLE_HOST, now)
}


pub fn run_syslog(config: &SyslogConfig, events: &[EcsEvent]) -> Result<(), ExportError> {
    let header = SyslogHeader {
        hostname: config.hostname.clone(),
        app_name: config.app_name.clone(),
    };
    let messages = events.iter().map(|event| format_message(&header, event)).collect::<Result<Vec<_>, _>>()?;
    match config.transport {
        SyslogTransport::Udp => send_datagrams(&config.address, &messages),
        SyslogTransport::Tls => {
            let ca = read_ca(config.ca_file.as_ref())?;
            let mut stream = open_stream(&config.address, client_config(ca.as_deref())?)?;
            write_frames(&mut stream, &messages)?;
            close(&mut stream)
        }
    }
}


/// Reloads of the export settings are appended to this log.
pub fn audit_into(log: AuditLog<File>) -> Box<SharedAuditFn> {
    Box::new(move |entry| append(&log, entry))
}


fn parse_number(text: &str) -> Result<u64, ExportError> {
    text.parse::<u64>().map_err(|_invalid| ExportError::Usage)
}


/// `webhook|syslog <config> <count> <first-sequence>`; sends sample events carrying sequence numbers and prints what happened.
pub fn run<Output: Write>(args: &[&str], out: &mut Output, resolve: &ResolveFn) -> Result<(), ExportError> {
    let now = OffsetDateTime::now_utc();
    match args {
        ["webhook", config_path, count, first] => {
            let events = sample_events(parse_number(count)?, parse_number(first)?, now);
            webhook_command(
                out,
                &load_export(Path::new(config_path))?,
                &events,
                resolve,
                &RetryPolicy::default(),
                &mut sleep,
                now,
            )
        }
        ["syslog", config_path, count, first] => {
            let events = sample_events(parse_number(count)?, parse_number(first)?, now);
            syslog_command(out, &load_export(Path::new(config_path))?, &events)
        }
        ["otlp", config_path, count, first] => {
            let events = sample_events(parse_number(count)?, parse_number(first)?, now);
            let path = Path::new(config_path);
            let log = open_file_log(&path.with_extension(AUDIT_EXTENSION))?;
            let context = ReloadContext {
                actor_id: SAMPLE_HOST.to_string(),
                tenant: SAMPLE_HOST.to_string(),
                module: AUDIT_MODULE.to_string(),
                target: config_path.to_string(),
                request_id: AUDIT_REQUEST_ID.to_string(),
            };
            let engine = open_export_engine(path, audit_into(log), context)?;
            otlp_command(out, &engine, &events, &RetryPolicy::default(), &mut sleep, now)
        }
        _ => Err(ExportError::Usage),
    }
}


fn say<Output: Write>(out: &mut Output, text: &str) -> Result<(), ExportError> {
    writeln!(out, "{text}").map_err(|source| ExportError::Io {
        context: "write output".to_string(),
        source,
    })
}


pub fn webhook_command<Output: Write>(
    out: &mut Output,
    config: &ExportConfig,
    events: &[EcsEvent],
    resolve: &ResolveFn,
    policy: &RetryPolicy,
    pause: &mut SleepFn,
    now: OffsetDateTime,
) -> Result<(), ExportError> {
    let webhook = config.webhook.as_ref().ok_or(ExportError::MissingSection("webhook"))?;
    report_to(out, &run_webhook(webhook, events, resolve, policy, pause, now)?)
}


/// Uses the settings the engine holds now, so a live swap applies from the next run.
pub fn otlp_command<Output: Write>(
    out: &mut Output,
    engine: &ReloadEngine<ExportConfig>,
    events: &[EcsEvent],
    policy: &RetryPolicy,
    pause: &mut SleepFn,
    now: OffsetDateTime,
) -> Result<(), ExportError> {
    let settings = current_config(engine);
    let otlp = settings.otlp.as_ref().ok_or(ExportError::MissingSection("otlp"))?;
    report_to(out, &run_otlp(otlp, events, policy, pause, now)?)
}


pub fn report_to<Output: Write>(out: &mut Output, report: &ExportReport) -> Result<(), ExportError> {
    say(
        out,
        &format!(
            "sent={} buffered={} drained={} dropped={}",
            report.sent_batches, report.buffered_batches, report.drained_batches, report.dropped_events
        ),
    )?;
    report
        .alert
        .iter()
        .try_for_each(|alert| to_json(alert).and_then(|json| say(out, &format!("alert {json}"))))
}


pub fn syslog_command<Output: Write>(out: &mut Output, config: &ExportConfig, events: &[EcsEvent]) -> Result<(), ExportError> {
    let syslog = config.syslog.as_ref().ok_or(ExportError::MissingSection("syslog"))?;
    run_syslog(syslog, events)?;
    say(out, &format!("sent={}", events.len()))
}
