mod common;


use common::types::TestResult;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use std::fs;
use std::io::{self, Write};
use tempfile::tempdir;
use traces_ingest::cli::{run_cli, write_report, CliError, MAX_PRINTED_ROWS, USAGE};
use traces_ingest::decode::decode_traces;
use traces_ingest::model::Limits;
use traces_ingest::sampling::Sampling;


const NOW: u64 = 1_700_000_000_000_000_000;


const SPANS: u8 = 12;


const FIXTURE_NOW: u64 = 1_800_000_000_000_000_000;


const ID_LEN: usize = 16;


const SPAN_LEN: usize = 8;


const BAD_BYTE: u8 = 0xff;


struct Failing;


struct Budget {
    left: usize,
}


impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let taken = bytes.len().min(self.left);
        self.left -= taken;
        if taken == 0 {
            Err(io::Error::other("full"))
        } else {
            Ok(taken)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


impl Write for Failing {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn request(spans: u8) -> Vec<u8> {
    let built = (1..=spans)
        .map(|seed| Span {
            trace_id: vec![seed; ID_LEN],
            span_id: vec![seed; SPAN_LEN],
            name: "op".to_string(),
            start_time_unix_nano: NOW,
            end_time_unix_nano: NOW,
            ..Default::default()
        })
        .collect();
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: built,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}


fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(ToString::to_string).collect()
}


#[test]
fn the_report_lists_counts_and_the_first_rows() -> TestResult {
    let dir = tempdir()?;
    let request_path = dir.path().join("request.pb");
    let sampling_path = dir.path().join("sampling.yaml");
    fs::write(&request_path, request(SPANS))?;
    fs::write(&sampling_path, "default_ratio: 1\n")?;
    let mut out = Vec::new();
    run_cli(
        &args(&[&request_path.to_string_lossy(), &sampling_path.to_string_lossy(), "acme"]),
        NOW,
        &mut out,
    )?;
    let text = String::from_utf8(out)?;
    assert!(text.starts_with("tenant acme\nrows 12\nsampled_out 0\nrefusal None\n"));
    assert_eq!(text.lines().filter(|line| line.starts_with("row ")).count(), MAX_PRINTED_ROWS);
    assert!(text.contains("service unknown_service name op status Unset"));
    Ok(())
}


#[test]
fn dropped_reasons_and_refusals_are_printed() -> TestResult {
    let bad = Span {
        name: "op".to_string(),
        ..Default::default()
    };
    let bytes = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![bad],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec();
    let outcome = decode_traces(&bytes, "acme", &Limits::default(), &Sampling::default(), NOW);
    let mut out = Vec::new();
    write_report(&outcome, &mut out)?;
    assert!(String::from_utf8(out)?.contains("dropped bad_id 1\n"));
    let refused = decode_traces(&[BAD_BYTE], "acme", &Limits::default(), &Sampling::default(), NOW);
    let mut refusal_out = Vec::new();
    write_report(&refused, &mut refusal_out)?;
    assert!(String::from_utf8(refusal_out)?.contains("refusal Some(Malformed("));
    Ok(())
}


#[test]
fn a_write_failure_at_any_byte_is_reported() -> TestResult {
    let bad = Span {
        name: "op".to_string(),
        ..Default::default()
    };
    let good = Span {
        trace_id: vec![1; ID_LEN],
        span_id: vec![1; SPAN_LEN],
        start_time_unix_nano: NOW,
        end_time_unix_nano: NOW,
        ..Default::default()
    };
    let bytes = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![bad, good],
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec();
    let outcome = decode_traces(&bytes, "acme", &Limits::default(), &Sampling::default(), NOW);
    let mut full = Vec::new();
    write_report(&outcome, &mut full)?;
    assert!((0..full.len()).all(|left| write_report(&outcome, &mut Budget { left }).is_err()));
    assert!(write_report(&outcome, &mut Budget { left: full.len() }).is_ok());
    Ok(())
}


#[test]
fn every_write_failure_is_reported() -> TestResult {
    let outcome = decode_traces(&request(1), "acme", &Limits::default(), &Sampling::default(), NOW);
    assert!(write_report(&outcome, &mut Failing).is_err());
    let counts_only = decode_traces(&request(0), "acme", &Limits::default(), &Sampling::default(), NOW);
    assert!(write_report(&counts_only, &mut Failing).is_err());
    let dir = tempdir()?;
    let request_path = dir.path().join("request.pb");
    let sampling_path = dir.path().join("sampling.yaml");
    fs::write(&request_path, request(1))?;
    fs::write(&sampling_path, "{}")?;
    let result = run_cli(
        &args(&[&request_path.to_string_lossy(), &sampling_path.to_string_lossy(), "acme"]),
        NOW,
        &mut Failing,
    );
    assert!(matches!(result, Err(CliError::Output(_))));
    Ok(())
}


#[test]
fn failures_have_fixed_text() -> TestResult {
    let dir = tempdir()?;
    let request_path = dir.path().join("request.pb");
    let sampling_path = dir.path().join("sampling.yaml");
    let missing = dir.path().join("missing");
    fs::write(&request_path, request(1))?;
    let request_text = request_path.to_string_lossy().to_string();
    let sampling_text = sampling_path.to_string_lossy().to_string();
    let missing_text = missing.to_string_lossy().to_string();
    let mut out = Vec::new();
    let usage = run_cli(&args(&["only"]), NOW, &mut out).err().ok_or("usage")?;
    assert_eq!(usage.to_string(), USAGE);
    let no_request = run_cli(&args(&[&missing_text, &sampling_text, "acme"]), NOW, &mut out)
        .err()
        .ok_or("request")?;
    assert_eq!(no_request.to_string(), "the request file could not be read");
    let no_sampling = run_cli(&args(&[&request_text, &missing_text, "acme"]), NOW, &mut out)
        .err()
        .ok_or("sampling")?;
    assert_eq!(no_sampling.to_string(), "the sampling file could not be read");
    fs::write(&sampling_path, [BAD_BYTE])?;
    let binary = run_cli(&args(&[&request_text, &sampling_text, "acme"]), NOW, &mut out)
        .err()
        .ok_or("text")?;
    assert_eq!(binary.to_string(), "the sampling file is not UTF-8");
    fs::write(&sampling_path, "default_ratio: 2\n")?;
    let refused = run_cli(&args(&[&request_text, &sampling_text, "acme"]), NOW, &mut out)
        .err()
        .ok_or("refused")?;
    assert_eq!(refused.to_string(), "the sampling file is refused");
    assert!(out.is_empty());
    assert_eq!(CliError::Output(io::Error::other("x")).to_string(), "the report could not be written");
    Ok(())
}


#[test]
fn the_sdk_fixture_keeps_every_error_span_and_whole_traces() -> TestResult {
    let dir = tempdir()?;
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/otel-sdk-two-services.pb");
    let sampling_path = dir.path().join("sampling.yaml");
    let run_with = |yaml: &str| -> Result<String, Box<dyn std::error::Error>> {
        fs::write(&sampling_path, yaml)?;
        let mut out = Vec::new();
        run_cli(&args(&[fixture, &sampling_path.to_string_lossy(), "acme"]), FIXTURE_NOW, &mut out)?;
        Ok(String::from_utf8(out)?)
    };
    assert!(run_with("default_ratio: 0\nerror_ratio: 1\n")?.contains("rows 40\nsampled_out 120\n"));
    assert!(run_with("default_ratio: 0.5\nerror_ratio: 1\n")?.contains("rows 112\nsampled_out 48\n"));
    assert!(run_with("default_ratio: 0.5\n")?.contains("rows 96\nsampled_out 64\n"));
    assert!(run_with("default_ratio: 1\n")?.contains("rows 160\nsampled_out 0\n"));
    Ok(())
}
