use crate::settings::IngestSettings;
use crate::types::{AckToken, ClockFn, SinkFn, SleepFn};
use core_config::reload::ReloadEngine;
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;


/// Opaque bus payload and the token that acknowledges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub payload: Vec<u8>,
    pub token: AckToken,
}


/// A validated payload as the sink receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub payload: Vec<u8>,
    pub timestamp: OffsetDateTime,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    pub token: AckToken,
    pub reason: String,
}


/// The parts of an ECS document the batcher requires; every other field is left to the sink.
#[derive(Debug, Deserialize)]
pub struct EcsEnvelope {
    #[serde(rename = "@timestamp", with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub ecs: EcsVersion,
    pub event: serde_json::Map<String, serde_json::Value>,
}


#[derive(Debug, Deserialize)]
pub struct EcsVersion {
    pub version: String,
}


#[derive(Debug, Default)]
pub struct Batch {
    pub documents: Vec<(AckToken, Document)>,
    pub dead: Vec<DeadLetter>,
    pub bytes: usize,
    pub opened_at: Option<OffsetDateTime>,
}


/// `acknowledge` is safe to ack on the bus; `unacknowledged` must be redelivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushReport {
    pub acknowledge: Vec<AckToken>,
    pub unacknowledged: Vec<AckToken>,
    pub dead_letters: Vec<DeadLetter>,
    pub delivered: usize,
    pub sink_error: Option<String>,
}


pub struct Batcher {
    pub settings: Arc<ReloadEngine<IngestSettings>>,
    pub batch: Batch,
    pub sink: Box<SinkFn>,
    pub clock: Box<ClockFn>,
    pub sleep: Box<SleepFn>,
}
