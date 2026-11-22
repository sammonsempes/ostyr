mod common;


use agent_channel::model::{MAX_SHELL_BYTES_PER_SESSION, MAX_SHELL_FRAMES_PER_SESSION, MAX_SHELL_FRAME_BYTES};
use common::types::TestResult;
use remote_shell::recording::{DEFAULT_MAX_FRAMES, DEFAULT_MAX_RECORDING_BYTES, FIXED_BODY_BYTES, MAX_FRAME_BYTES, PREFIX_BYTES};


#[test]
fn a_shell_frame_of_the_channel_fits_one_recording_frame() -> TestResult {
    assert_eq!(MAX_SHELL_FRAME_BYTES, MAX_FRAME_BYTES);
    Ok(())
}


#[test]
fn the_channel_frame_budget_stays_under_the_default_recording_frames() -> TestResult {
    const { assert!(MAX_SHELL_FRAMES_PER_SESSION <= DEFAULT_MAX_FRAMES) };
    Ok(())
}


#[test]
fn the_channel_byte_budget_with_the_recording_overhead_stays_under_the_default_recording_bytes() -> TestResult {
    const PER_FRAME: u64 = PREFIX_BYTES + FIXED_BODY_BYTES as u64;
    const { assert!(MAX_SHELL_BYTES_PER_SESSION + MAX_SHELL_FRAMES_PER_SESSION * PER_FRAME <= DEFAULT_MAX_RECORDING_BYTES) };
    Ok(())
}
