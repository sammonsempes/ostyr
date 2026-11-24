#![cfg(feature = "ebpf-load")]
//! The production loader: load the exec probe from checked bytes, attach it, drain its ring. Proved by the `ebpf` workflow and the lab only.

use crate::btf::{read_task_offsets, require_64_bit, VMLINUX_BTF_PATH};
use crate::drain::{decode_batch, finish_drain, poll_loop, Drained};
use crate::error::{attach_error, ebpf_error, program_load_error, LoadError};
use crate::limiter::Limiter;
use crate::object::read_object;
use crate::shape::{check_object_bytes, DROPS_NAME, PROGRAM_NAME, RING_NAME};
use aya::maps::{MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use std::path::Path;
use std::sync::atomic::AtomicBool;


const DROP_SLOT: u32 = 0;


pub struct Probe {
    pub ebpf: Ebpf,
    pub ring: RingBuf<MapData>,
    pub drops: PerCpuArray<MapData, u64>,
    pub limiter: Limiter,
    pub baseline: u64,
}


/// Loads the probe from bytes already judged by `read_object`; the same bytes are parsed and judged by `check_object_bytes` first.
pub fn load_exec_probe_from_bytes(bytes: &[u8]) -> Result<Probe, LoadError> {
    require_64_bit(usize::BITS)?;
    let offsets = read_task_offsets(Path::new(VMLINUX_BTF_PATH))?;
    check_object_bytes(bytes)?;
    let real_parent = u64::from(offsets.real_parent);
    let tgid = u64::from(offsets.tgid);
    let mut ebpf = EbpfLoader::new()
        .override_global("REAL_PARENT_OFFSET", &real_parent, true)
        .override_global("TGID_OFFSET", &tgid, true)
        .load(bytes)
        .map_err(|error| ebpf_error(&error))?;
    let program: &mut TracePoint = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or(LoadError::MissingProgram)?
        .try_into()
        .map_err(|_| LoadError::WrongProgramType)?;
    program.load().map_err(|error| program_load_error(&error))?;
    program.attach("sched", PROGRAM_NAME).map_err(|error| attach_error(&error))?;
    let ring = ebpf
        .take_map(RING_NAME)
        .ok_or(LoadError::TakeMap(RING_NAME))
        .and_then(|map| RingBuf::try_from(map).map_err(|_| LoadError::TakeMap(RING_NAME)))?;
    let drops = ebpf
        .take_map(DROPS_NAME)
        .ok_or(LoadError::TakeMap(DROPS_NAME))
        .and_then(|map| PerCpuArray::try_from(map).map_err(|_| LoadError::TakeMap(DROPS_NAME)))?;
    Ok(Probe {
        ebpf,
        ring,
        drops,
        limiter: Limiter::default(),
        baseline: 0,
    })
}


/// Reads the object at `path` through the checked handle, then loads it (production passes `EXEC_OBJECT_PATH`); dropping the probe detaches and closes everything.
pub fn load_exec_probe(path: &Path) -> Result<Probe, LoadError> {
    let bytes = read_object(path)?;
    load_exec_probe_from_bytes(&bytes)
}


/// Sums the one-slot per-CPU drop counter over the CPUs.
pub fn read_dropped(drops: &PerCpuArray<MapData, u64>) -> Result<u64, MapError> {
    let per_cpu = drops.get(&DROP_SLOT, 0)?;
    Ok(per_cpu.iter().fold(0, |sum: u64, value| sum.saturating_add(*value)))
}


/// Drains at most `max_records` without waiting; every decision is in `drain.rs`, this only reads the ring and the counter and logs the one warn line.
pub fn drain_exec(probe: &mut Probe, max_records: usize) -> Drained {
    let ring = &mut probe.ring;
    let mut raw = std::iter::from_fn(|| ring.next().map(|item| item.to_vec()));
    let batch = decode_batch(&mut raw, &mut probe.limiter, max_records);
    let current = read_dropped(&probe.drops).ok();
    let (drained, warning) = finish_drain(batch, max_records, &mut probe.baseline, current);
    warning.iter().for_each(|text| tracing::warn!("{text}"));
    drained
}


/// Polls at the fixed interval of `drain::wait_after`; `more_pending` never causes an immediate second poll.
pub fn poll_exec(probe: &mut Probe, stop: &AtomicBool, max_polls: u32, max_records: usize, deliver: &mut dyn FnMut(Drained)) -> u32 {
    poll_loop(stop, max_polls, &mut || drain_exec(probe, max_records), deliver, &mut std::thread::sleep)
}
