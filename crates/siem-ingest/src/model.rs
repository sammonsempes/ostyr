use crate::settings::IngestSettings;
use crate::types::{AckFn, AckToken, ClockFn, DeadLetterFn, FetchFn, PendingMap, SinkFn, SleepFn};
use core_config::reload::ReloadEngine;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;


/// Bus payload, tenant (from the authenticated producer, never the payload) and ack token; no `Debug`, so logs never print event bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub tenant: String,
    pub payload: Vec<u8>,
    pub token: AckToken,
}


/// A validated payload as the sink receives it; no `Debug`, so a log never prints event bytes.
#[derive(Clone, PartialEq, Eq)]
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


#[derive(Default)]
pub struct Batch {
    pub tenant: Option<String>,
    pub documents: Vec<(AckToken, Document)>,
    pub dead: Vec<DeadLetter>,
    pub bytes: usize,
    pub opened_at: Option<OffsetDateTime>,
}


/// `acknowledge` is safe to ack on the bus; `unacknowledged` must be redelivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushReport {
    pub tenant: String,
    pub acknowledge: Vec<AckToken>,
    pub unacknowledged: Vec<AckToken>,
    pub dead_letters: Vec<DeadLetter>,
    pub delivered: usize,
    pub sink_error: Option<String>,
}


/// One bus message as the consumer hands it over: the subject carries the tenant. No `Debug`, so a log never prints event bytes.
pub struct Delivery {
    pub subject: String,
    pub payload: Vec<u8>,
    pub token: AckToken,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckAction {
    Ack,
    Nak,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CycleReport {
    pub fetched: usize,
    pub refused: usize,
    pub acknowledged: usize,
    pub redelivered: usize,
    pub dead_lettered: usize,
    pub ack_failures: usize,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoopReport {
    pub cycles: u64,
    pub fetch_failures: u64,
}


pub struct Wiring {
    pub fetch: Box<FetchFn>,
    pub ack: Box<AckFn>,
    pub dead_letter: Box<DeadLetterFn>,
}


/// The batcher fed by the bus; `pending` keeps each in-flight message for dead-lettering, `carry` the ones refused until a flush.
pub struct Pipeline {
    pub batcher: Batcher,
    pub wiring: Wiring,
    pub pending: PendingMap,
    pub carry: Vec<Message>,
}


pub struct Batcher {
    pub settings: Arc<ReloadEngine<IngestSettings>>,
    pub batch: Batch,
    pub sink: Box<SinkFn>,
    pub clock: Box<ClockFn>,
    pub sleep: Box<SleepFn>,
}


/// One NATS connection with its durable consumer; `held` keeps each delivered message until its acknowledgement.
pub struct Session {
    pub client: async_nats::Client,
    pub jetstream: async_nats::jetstream::Context,
    pub consumer: async_nats::jetstream::consumer::PullConsumer,
    pub held: HashMap<AckToken, async_nats::jetstream::Message>,
    pub dropped: Arc<AtomicBool>,
    pub settings: Arc<IngestSettings>,
}


/// The runtime and the settings engine the three `Wiring` closures share; the session is replaced after any failure.
pub struct Link {
    pub runtime: tokio::runtime::Runtime,
    pub settings: Arc<ReloadEngine<IngestSettings>>,
    pub session: Mutex<Option<Session>>,
    pub next_token: AtomicU64,
}
