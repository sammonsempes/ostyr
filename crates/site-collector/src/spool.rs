use crate::dirfs::{
    create_append, directory_facts, open_append, open_directory, open_read, open_write, regular_file_names, remove_named, sync_directory,
};
use crate::epoch::open_epoch;
use crate::error::SpoolError;
use crate::frame::{encode_frame, frame_len, read_frame};
use crate::spool_model::{
    DirectoryFacts, FrameRead, Priority, Record, Segment, Spool, SpoolConfig, SpoolStats, FRAME_HEADER_BYTES, GROUP_OR_OTHER_WRITE,
    LOW_WATER_DIVISOR, MAX_DIRECTORY_ENTRIES, MAX_FRAME_BYTES, MAX_SEGMENTS_IN_TOTAL, MAX_SEGMENT_BYTES, MAX_SEGMENT_FILES, MIN_SEGMENTS_IN_TOTAL,
    SEGMENT_NAME_DIGITS, SEGMENT_SUFFIX,
};
use crate::types::{DirHandle, DirSyncFn, FrameWriter, SegmentList};
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};


pub fn segment_name(first_sequence: u64) -> String {
    format!("{first_sequence:0width$}{SEGMENT_SUFFIX}", width = SEGMENT_NAME_DIGITS)
}


pub fn segment_path(dir: &Path, first_sequence: u64) -> PathBuf {
    dir.join(segment_name(first_sequence))
}


pub fn parse_segment_name(name: &str) -> Option<u64> {
    name.strip_suffix(SEGMENT_SUFFIX)
        .filter(|digits| digits.len() == SEGMENT_NAME_DIGITS && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
}


pub fn check_directory(facts: &DirectoryFacts) -> Result<(), SpoolError> {
    if !facts.is_directory {
        Err(SpoolError::NotDirectory)
    } else if facts.owner != facts.expected_owner {
        Err(SpoolError::WrongOwner)
    } else if facts.mode & GROUP_OR_OTHER_WRITE != 0 {
        Err(SpoolError::WritableByOthers)
    } else {
        Ok(())
    }
}


pub fn check_config(config: &SpoolConfig) -> Result<(), SpoolError> {
    let fits = (MAX_FRAME_BYTES..=MAX_SEGMENT_BYTES).contains(&config.segment_max_bytes)
        && config.total_max_bytes >= config.segment_max_bytes.saturating_mul(MIN_SEGMENTS_IN_TOTAL)
        && config.total_max_bytes <= config.segment_max_bytes.saturating_mul(MAX_SEGMENTS_IN_TOTAL);
    fits.then_some(()).ok_or(SpoolError::BadSizes)
}


fn end_sequence(segment: &Segment) -> u64 {
    segment
        .first_sequence
        .saturating_add(segment.low_records)
        .saturating_add(segment.high_records)
}


pub fn scan_segment(dir: &DirHandle, first_sequence: u64) -> Result<(Segment, bool), SpoolError> {
    let file = open_read(dir, &segment_name(first_sequence))?;
    let length = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut segment = Segment {
        first_sequence,
        bytes: 0,
        low_records: 0,
        high_records: 0,
    };
    let mut torn = false;
    let mut finished = false;
    for _ in 0..length / FRAME_HEADER_BYTES as u64 + 1 {
        if !finished {
            match read_frame(&mut reader, length - segment.bytes)? {
                FrameRead::Frame(record, total) if record.sequence == end_sequence(&segment) => {
                    segment.bytes += total;
                    match record.priority {
                        Priority::Low => segment.low_records += 1,
                        Priority::High => segment.high_records += 1,
                    }
                }
                FrameRead::End => finished = true,
                FrameRead::Frame(..) | FrameRead::Torn => {
                    torn = true;
                    finished = true;
                }
            }
        }
    }
    Ok((segment, torn))
}


fn create_segment(dir: &DirHandle, first_sequence: u64) -> Result<File, SpoolError> {
    Ok(create_append(dir, &segment_name(first_sequence))?)
}


fn list_segment_sequences(dir: &DirHandle) -> Result<Vec<u64>, SpoolError> {
    let mut sequences: Vec<u64> = regular_file_names(dir, MAX_DIRECTORY_ENTRIES)?
        .iter()
        .filter_map(|name| parse_segment_name(name))
        .collect();
    sequences.sort_unstable();
    (sequences.len() <= MAX_SEGMENT_FILES)
        .then_some(sequences)
        .ok_or(SpoolError::TooManySegments)
}


fn load_segments(dir: &DirHandle, sequences: &[u64]) -> Result<(SegmentList, u64), SpoolError> {
    let mut segments = SegmentList::new();
    let mut truncated = 0;
    let last_index = sequences.len().saturating_sub(1);
    for (index, first_sequence) in sequences.iter().enumerate() {
        let (segment, torn) = scan_segment(dir, *first_sequence)?;
        if torn {
            open_write(dir, &segment_name(*first_sequence))?.set_len(segment.bytes)?;
            truncated += 1;
            tracing::warn!(segment = *first_sequence, kept_bytes = segment.bytes, "truncated a torn spool tail");
        }
        if segment.bytes > 0 || index == last_index {
            segments.push_back(segment);
        } else {
            remove_named(dir, &segment_name(*first_sequence))?;
        }
    }
    Ok((segments, truncated))
}


pub fn open_spool(dir: &Path, config: SpoolConfig) -> Result<Spool, SpoolError> {
    check_config(&config)?;
    let handle = open_directory(dir)?;
    check_directory(&directory_facts(&handle)?)?;
    let sequences = list_segment_sequences(&handle)?;
    let (mut segments, truncated_tails) = load_segments(&handle, &sequences)?;
    if segments.is_empty() {
        create_segment(&handle, 0)?;
        segments.push_back(Segment {
            first_sequence: 0,
            bytes: 0,
            low_records: 0,
            high_records: 0,
        });
    }
    let epoch = open_epoch(&handle, segments.back().map_or(0, end_sequence))?;
    let first_active = segments.back().map_or(0, |segment| segment.first_sequence);
    let active = open_append(&handle, &segment_name(first_active))?;
    let mut spool = Spool {
        dir: handle,
        config,
        next_sequence: segments.back().map_or(0, end_sequence),
        total_bytes: segments.iter().map(|segment| segment.bytes).sum(),
        segments,
        active,
        dropped_low: 0,
        dropped_high: 0,
        truncated_tails,
        unlink_failures: 0,
        missing_segments: 0,
        saturated: false,
        epoch,
    };
    enforce_cap(&mut spool, 0)?;
    Ok(spool)
}


/// The segments holding a record in `from..to` flushed, then the directory, so those records and their file names survive a power cut.
pub fn sync_range(spool: &Spool, from: u64, to: u64) -> Result<(), SpoolError> {
    sync_range_with(spool, from, to, sync_directory)
}


/// `sync_range` with the directory sync injected.
pub fn sync_range_with(spool: &Spool, from: u64, to: u64, dir_sync: DirSyncFn) -> Result<(), SpoolError> {
    spool
        .segments
        .iter()
        .filter(|segment| segment.first_sequence < to && end_sequence(segment) > from)
        .try_for_each(|segment| -> Result<(), SpoolError> { Ok(open_read(&spool.dir, &segment_name(segment.first_sequence))?.sync_data()?) })
        .and_then(|()| dir_sync(&spool.dir).map_err(SpoolError::from))
}


fn rotate(spool: &mut Spool) -> Result<(), SpoolError> {
    spool.active = create_segment(&spool.dir, spool.next_sequence)?;
    spool.segments.push_back(Segment {
        first_sequence: spool.next_sequence,
        bytes: 0,
        low_records: 0,
        high_records: 0,
    });
    Ok(())
}


fn remove_segment_file(spool: &mut Spool, segment: &Segment) -> Result<(), SpoolError> {
    let removed = remove_named(&spool.dir, &segment_name(segment.first_sequence));
    let missing = matches!(&removed, Err(error) if error.kind() == io::ErrorKind::NotFound);
    spool.missing_segments += u64::from(missing);
    spool.unlink_failures += u64::from(removed.is_err() && !missing);
    (if missing { Ok(()) } else { removed }).map_err(SpoolError::from)
}


fn drop_victim(spool: &mut Spool) -> Result<(), SpoolError> {
    let sealed = spool.segments.len().saturating_sub(1);
    let index = spool
        .segments
        .iter()
        .take(sealed)
        .position(|segment| segment.high_records == 0)
        .unwrap_or(0);
    let victim = (sealed > 0).then(|| spool.segments.get(index).cloned()).flatten();
    victim.into_iter().try_for_each(|segment| -> Result<(), SpoolError> {
        remove_segment_file(spool, &segment)?;
        spool.segments.remove(index);
        spool.total_bytes = spool.total_bytes.saturating_sub(segment.bytes);
        spool.dropped_low += segment.low_records;
        spool.dropped_high += segment.high_records;
        spool.saturated = true;
        Ok(())
    })
}


pub fn enforce_cap(spool: &mut Spool, incoming: u64) -> Result<(), SpoolError> {
    for _ in 0..spool.segments.len() {
        if spool.total_bytes.saturating_add(incoming) > spool.config.total_max_bytes || spool.segments.len() > MAX_SEGMENTS_IN_TOTAL as usize {
            drop_victim(spool)?;
        }
    }
    Ok(())
}


pub fn write_whole(file: &mut File, frame: &[u8]) -> io::Result<()> {
    file.write_all(frame)
}


pub fn append(spool: &mut Spool, priority: Priority, payload: &[u8]) -> Result<u64, SpoolError> {
    append_with(spool, priority, payload, write_whole)
}


pub fn append_with(spool: &mut Spool, priority: Priority, payload: &[u8], writer: FrameWriter) -> Result<u64, SpoolError> {
    let sequence = spool.next_sequence;
    let size = frame_len(payload.len());
    let frame = encode_frame(&Record {
        priority,
        sequence,
        payload: payload.to_vec(),
    })?;
    let active_bytes = spool.segments.back().map_or(0, |segment| segment.bytes);
    if active_bytes > 0 && active_bytes + size > spool.config.segment_max_bytes {
        if spool.segments.len() >= MAX_SEGMENTS_IN_TOTAL as usize {
            drop_victim(spool)?;
        }
        rotate(spool)?;
    }
    enforce_cap(spool, size)?;
    let active_bytes_after = spool.segments.back().map_or(0, |segment| segment.bytes);
    writer(&mut spool.active, &frame).or_else(|error| spool.active.set_len(active_bytes_after).and(Err(error)))?;
    spool.segments.back_mut().into_iter().for_each(|segment| {
        segment.bytes += size;
        match priority {
            Priority::Low => segment.low_records += 1,
            Priority::High => segment.high_records += 1,
        }
    });
    spool.total_bytes += size;
    spool.next_sequence += 1;
    Ok(sequence)
}


pub fn acknowledge(spool: &mut Spool, sequence: u64) -> Result<(), SpoolError> {
    let acknowledged_end = sequence.saturating_add(1);
    let active_done = spool
        .segments
        .back()
        .is_some_and(|segment| segment.bytes > 0 && end_sequence(segment) <= acknowledged_end);
    if active_done {
        rotate(spool)?;
    }
    for _ in 0..spool.segments.len() {
        let front_done = spool.segments.len() > 1 && spool.segments.front().is_some_and(|segment| end_sequence(segment) <= acknowledged_end);
        if front_done {
            spool
                .segments
                .front()
                .cloned()
                .into_iter()
                .try_for_each(|segment| -> Result<(), SpoolError> {
                    remove_segment_file(spool, &segment)?;
                    spool.segments.pop_front();
                    spool.total_bytes = spool.total_bytes.saturating_sub(segment.bytes);
                    Ok(())
                })?;
        }
    }
    if spool.total_bytes <= spool.config.total_max_bytes / LOW_WATER_DIVISOR {
        spool.saturated = false;
    }
    Ok(())
}


fn read_segment(spool: &Spool, segment: &Segment, from: u64, limit: usize, out: &mut Vec<Record>) -> Result<(), SpoolError> {
    let mut reader = BufReader::new(open_read(&spool.dir, &segment_name(segment.first_sequence))?);
    let mut position = 0;
    for index in 0..segment.low_records + segment.high_records {
        let (record, total) = match read_frame(&mut reader, segment.bytes - position)? {
            FrameRead::Frame(record, total) => Ok((record, total)),
            FrameRead::End | FrameRead::Torn => Err(SpoolError::Corrupt(segment.first_sequence + index)),
        }?;
        position += total;
        if record.sequence >= from && out.len() < limit {
            out.push(record);
        }
    }
    Ok(())
}


pub fn read_from(spool: &Spool, sequence: u64, max_records: usize) -> Result<Vec<Record>, SpoolError> {
    let mut records = Vec::new();
    for segment in spool.segments.iter().filter(|segment| end_sequence(segment) > sequence) {
        read_segment(spool, segment, sequence, max_records, &mut records)?;
    }
    Ok(records)
}


pub fn spool_stats(spool: &Spool) -> SpoolStats {
    SpoolStats {
        dropped_low: spool.dropped_low,
        dropped_high: spool.dropped_high,
        truncated_tails: spool.truncated_tails,
        unlink_failures: spool.unlink_failures,
        missing_segments: spool.missing_segments,
        saturated: spool.saturated,
        total_bytes: spool.total_bytes,
        next_sequence: spool.next_sequence,
        segments: spool.segments.len(),
    }
}
