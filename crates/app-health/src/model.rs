//! Data types.

use serde::Deserialize;


#[derive(Debug, Clone, PartialEq)]
pub struct Tracking {
    pub reference_id: String,
    pub reference_name: Option<String>,
    pub stratum: Option<u32>,
    pub system_time_offset: Option<f64>,
    pub last_offset: Option<f64>,
    pub rms_offset: Option<f64>,
    pub frequency: Option<f64>,
    pub residual_frequency: Option<f64>,
    pub skew: Option<f64>,
    pub root_delay: Option<f64>,
    pub root_dispersion: Option<f64>,
    pub update_interval: Option<f64>,
    pub leap_status: LeapStatus,
    pub rejected_fields: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapStatus {
    Normal,
    InsertSecond,
    DeleteSecond,
    NotSynchronised,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSync {
    pub ntp_enabled: Option<bool>,
    pub synchronized: Option<bool>,
    pub timezone: Option<String>,
    pub rejected_fields: usize,
}


#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub max_offset_seconds: f64,
    pub max_stratum: u32,
    pub require_synchronized: bool,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindReason {
    NoOffset,
    NotSynchronised,
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NtpHealth {
    Healthy,
    BlindSpot(BlindReason),
    Drift { offset: f64 },
    Stratum { stratum: u32 },
    Unsynchronised,
}


#[derive(Debug, Clone, PartialEq)]
pub struct Measure {
    pub name: &'static str,
    pub unit: &'static str,
    pub value: f64,
}
