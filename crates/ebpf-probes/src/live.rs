#![cfg(feature = "ebpf-live")]
//! Reads the kernel object's drop counter.

use aya::maps::{MapData, MapError, PerCpuArray};


const DROP_SLOT: u32 = 0;


/// Sums the one-slot per-CPU drop counter over the CPUs (at most one value per CPU).
pub fn read_dropped(drops: &PerCpuArray<MapData, u64>) -> Result<u64, MapError> {
    let per_cpu = drops.get(&DROP_SLOT, 0)?;
    Ok(per_cpu.iter().fold(0, |sum: u64, value| sum.saturating_add(*value)))
}
