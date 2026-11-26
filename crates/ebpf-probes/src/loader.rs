#![cfg(feature = "ebpf-load")]
//! The production loader: load the exec probe from checked bytes, attach it, drain its ring. Proved by the `ebpf` workflow and the lab only.

use crate::btf::{read_task_offsets, require_64_bit, VMLINUX_BTF_PATH};
use crate::drain::{
    decode_batch, finish_drain, may_proceed, poll_loop, sum_per_cpu, Batch, Decoder, Drained, EXEC_DECODER, FILE_DECODER, MAX_DRAIN_PER_POLL,
};
use crate::error::{attach_error, ebpf_error, program_load_error, settle_probe, split_settled, FileProbeUnavailable, LoadError};
use crate::limiter::Limiter;
use crate::object::{read_object, EXEC_OBJECT_PATH};
use crate::record::{ExecRecord, FileRecord};
use crate::shape::{check_object_bytes_for, AttachKind, ProbeSpec, RecordKind, EXEC_PROBE, PROBE_TABLE};
use aya::maps::{MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use std::path::Path;
use std::sync::atomic::AtomicBool;


const DROP_SLOT: u32 = 0;


pub struct ProbeState {
    pub spec: ProbeSpec,
    pub ring: RingBuf<MapData>,
    pub drops: PerCpuArray<MapData, u64>,
    pub limiter: Limiter,
    pub baseline: u64,
}


pub struct Probe {
    pub ebpf: Ebpf,
    pub states: Vec<ProbeState>,
    pub unavailable: Vec<FileProbeUnavailable>,
}


pub enum ProbeDrained {
    Exec(Drained<ExecRecord>),
    File(Drained<FileRecord>),
}


pub struct ProbeDrain {
    pub name: &'static str,
    pub drained: ProbeDrained,
}


fn tracepoint_of<'a>(ebpf: &'a mut Ebpf, spec: &ProbeSpec) -> Result<&'a mut TracePoint, LoadError> {
    ebpf.program_mut(spec.program)
        .ok_or(LoadError::MissingProgram(spec.program))?
        .try_into()
        .map_err(|_| LoadError::WrongProgramType(spec.program))
}


fn take_state(ebpf: &mut Ebpf, spec: &ProbeSpec) -> Result<ProbeState, LoadError> {
    tracepoint_of(ebpf, spec)?.load().map_err(|error| program_load_error(spec.name, &error))?;
    let ring = ebpf
        .take_map(spec.ring)
        .ok_or(LoadError::TakeMap(spec.ring))
        .and_then(|map| RingBuf::try_from(map).map_err(|_| LoadError::TakeMap(spec.ring)))?;
    let drops = ebpf
        .take_map(spec.drops)
        .ok_or(LoadError::TakeMap(spec.drops))
        .and_then(|map| PerCpuArray::try_from(map).map_err(|_| LoadError::TakeMap(spec.drops)))?;
    Ok(ProbeState {
        spec: *spec,
        ring,
        drops,
        limiter: Limiter::default(),
        baseline: 0,
    })
}


fn report_unavailable(lost: &FileProbeUnavailable) {
    tracing::error!("{lost}");
}


/// Loads every program of `table` and takes its maps from bytes already judged by `read_object`, without attaching; `check_object_bytes_for` judges the same bytes once, first.
pub fn prepare_probes_from_bytes(bytes: &[u8], table: &[ProbeSpec]) -> Result<Probe, LoadError> {
    require_64_bit(usize::BITS)?;
    let offsets = read_task_offsets(Path::new(VMLINUX_BTF_PATH))?;
    check_object_bytes_for(bytes, table)?;
    let real_parent = u64::from(offsets.real_parent);
    let tgid = u64::from(offsets.tgid);
    let mut ebpf = EbpfLoader::new()
        .override_global("REAL_PARENT_OFFSET", &real_parent, true)
        .override_global("TGID_OFFSET", &tgid, true)
        .load(bytes)
        .map_err(|error| ebpf_error(&error))?;
    let settled = table
        .iter()
        .map(|spec| settle_probe(spec, take_state(&mut ebpf, spec)))
        .collect::<Result<Vec<_>, _>>()?;
    let (states, unavailable) = split_settled(settled);
    unavailable.iter().for_each(report_unavailable);
    Ok(Probe { ebpf, states, unavailable })
}


/// Loads the production table without attaching.
pub fn prepare_exec_probe_from_bytes(bytes: &[u8]) -> Result<Probe, LoadError> {
    prepare_probes_from_bytes(bytes, &PROBE_TABLE)
}


fn attach_state(ebpf: &mut Ebpf, spec: &ProbeSpec) -> Result<(), LoadError> {
    let program = tracepoint_of(ebpf, spec)?;
    match spec.attach {
        AttachKind::TracePoint { category, name } => program.attach(category, name).map(drop).map_err(|error| attach_error(spec.name, &error)),
    }
}


/// Attaches every loaded program; a failing exec probe is the whole failure, any other probe that fails to attach is dropped from the states, logged and named in `Probe.unavailable`; dropping the probe detaches whatever was attached.
pub fn attach_probes(probe: &mut Probe) -> Result<(), LoadError> {
    let specs: Vec<ProbeSpec> = probe.states.iter().map(|state| state.spec).collect();
    let settled = specs
        .iter()
        .map(|spec| settle_probe(spec, attach_state(&mut probe.ebpf, spec)))
        .collect::<Result<Vec<_>, _>>()?;
    let (_, lost) = split_settled(settled);
    lost.iter().for_each(report_unavailable);
    probe.states.retain(|state| !lost.iter().any(|gone| gone.probe == state.spec.name));
    probe.unavailable.extend(lost);
    Ok(())
}


/// Attaches the exec program alone (the agent drains no other ring yet); every other loaded program stays unattached, so it costs nothing. Dropping the probe detaches it.
pub fn attach_exec_probe(probe: &mut Probe) -> Result<(), LoadError> {
    let specs: Vec<ProbeSpec> = probe
        .states
        .iter()
        .map(|state| state.spec)
        .filter(|spec| spec.kind == RecordKind::Exec)
        .collect();
    specs.iter().try_for_each(|spec| attach_state(&mut probe.ebpf, spec))
}


/// Loads and attaches the probe from bytes already judged by `read_object`.
pub fn load_exec_probe_from_bytes(bytes: &[u8]) -> Result<Probe, LoadError> {
    let mut probe = prepare_exec_probe_from_bytes(bytes)?;
    attach_exec_probe(&mut probe)?;
    Ok(probe)
}


/// Reads the object at `path` through the checked handle, then loads it (production passes `EXEC_OBJECT_PATH`); dropping the probe detaches and closes everything.
pub fn load_exec_probe(path: &Path) -> Result<Probe, LoadError> {
    let bytes = read_object(path)?;
    load_exec_probe_from_bytes(&bytes)
}


/// Sums the one-slot per-CPU drop counter over the CPUs.
pub fn read_dropped(drops: &PerCpuArray<MapData, u64>) -> Result<u64, MapError> {
    let per_cpu = drops.get(&DROP_SLOT, 0)?;
    Ok(sum_per_cpu(&per_cpu))
}


/// Drains one probe without waiting; every decision is in `drain.rs`, this only reads the ring and the counter and logs the one warn line.
fn drain_ring<Item>(state: &mut ProbeState, max_records: usize, decoder: &Decoder<Item>) -> Drained<Item> {
    let ring = &mut state.ring;
    let mut raw = std::iter::from_fn(|| ring.next().map(|item| item.to_vec()));
    let batch = decode_batch(&mut raw, &mut state.limiter, max_records, decoder);
    let current = read_dropped(&state.drops).ok();
    let name = state.spec.name;
    let (drained, warning) = finish_drain(name, batch, max_records, &mut state.baseline, current);
    warning.iter().for_each(|text| tracing::warn!("{name}: {text}"));
    drained
}


fn drain_state(state: &mut ProbeState, max_records: usize) -> ProbeDrained {
    match state.spec.kind {
        RecordKind::Exec => ProbeDrained::Exec(drain_ring(state, max_records, &EXEC_DECODER)),
        RecordKind::File => ProbeDrained::File(drain_ring(state, max_records, &FILE_DECODER)),
    }
}


/// The one shared drain: every probe of the table in table order, at most `max_records` each, one report and one count per probe.
pub fn drain_probes(probe: &mut Probe, max_records: usize) -> Vec<ProbeDrain> {
    probe
        .states
        .iter_mut()
        .map(|state| ProbeDrain {
            name: state.spec.name,
            drained: drain_state(state, max_records),
        })
        .collect()
}


/// Drains the exec probe alone; an exec probe missing from the table is a loud unknown kernel drop count, never an empty success.
pub fn drain_exec(probe: &mut Probe, max_records: usize) -> Drained {
    match probe.states.iter_mut().find(|state| state.spec.name == EXEC_PROBE.name) {
        Some(state) => drain_ring(state, max_records, &EXEC_DECODER),
        None => finish_drain(EXEC_PROBE.name, Batch::default(), max_records, &mut 0, None).0,
    }
}


/// Polls at the fixed interval of `drain::wait_after`; `more_pending` never causes an immediate second poll.
pub fn poll_exec(probe: &mut Probe, stop: &AtomicBool, max_polls: u32, max_records: usize, deliver: &mut dyn FnMut(Drained)) -> u32 {
    poll_loop(stop, max_polls, &mut || drain_exec(probe, max_records), deliver, &mut std::thread::sleep)
}


/// The whole life of one probe on the calling thread: load from `EXEC_OBJECT_PATH` without attaching, check `stop`, attach, poll (its first step reads `stop` again) until `stop` is set or `max_polls` is reached; dropping it at the end unloads the program.
pub fn run_exec_probe(stop: &AtomicBool, max_polls: u32, on_attached: &mut dyn FnMut(), deliver: &mut dyn FnMut(Drained)) -> Result<u32, LoadError> {
    let bytes = read_object(Path::new(EXEC_OBJECT_PATH))?;
    let mut probe = prepare_exec_probe_from_bytes(&bytes)?;
    let polls = if may_proceed(stop) {
        attach_exec_probe(&mut probe)?;
        on_attached();
        poll_exec(&mut probe, stop, max_polls, MAX_DRAIN_PER_POLL, deliver)
    } else {
        0
    };
    Ok(polls)
}
