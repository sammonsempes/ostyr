//! Reads a spooled flow frame back, strictly: the disk is a trust boundary like the network.

use crate::error::FlowFrameError;
use crate::flow_model::{FlowBatch, FlowRecord, FLOW_FRAME_VERSION, MAX_FLOW_FRAME_BYTES};
use serde_json::{Map, Value};
use std::net::IpAddr;


/// The exporter and the record of a frame: size bound first, then the version, then every field of the record by name, type and range.
pub fn decode_flow_frame(payload: &[u8]) -> Result<(IpAddr, FlowRecord), FlowFrameError> {
    if payload.len() > MAX_FLOW_FRAME_BYTES {
        Err(FlowFrameError::TooLarge(payload.len()))
    } else {
        let mut fields: Map<String, Value> = serde_json::from_slice(payload)?;
        let version = fields
            .remove("v")
            .and_then(|value| value.as_u64())
            .ok_or(FlowFrameError::MissingVersion)?;
        if version == u64::from(FLOW_FRAME_VERSION) {
            let exporter_value = fields.remove("exporter").ok_or(FlowFrameError::MissingExporter)?;
            let exporter: IpAddr = serde_json::from_value(exporter_value)?;
            let record: FlowRecord = serde_json::from_value(Value::Object(fields))?;
            Ok((exporter, record))
        } else {
            Err(FlowFrameError::UnknownVersion(version))
        }
    }
}


/// A batch of one record; the frame carries no header fields, so they are zero.
pub fn single_flow_batch(record: FlowRecord) -> FlowBatch {
    FlowBatch {
        export_unix_ms: 0,
        exporter_uptime_ms: 0,
        sequence: 0,
        engine_type: 0,
        engine_id: 0,
        sampling_mode: 0,
        sampling_interval: 0,
        records: vec![record],
    }
}
