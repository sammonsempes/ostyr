use backup_monitor::error::BackupError;
use backup_monitor::model::Limits;
use backup_monitor::parse::parse_restic;
use std::error::Error;


const MEBIBYTE: usize = 1024 * 1024;


const LISTING_BYTES: usize = 8 * MEBIBYTE;


const SHAPE_BUDGET_KIB: u64 = 64 * 1024;


const SHAPES: usize = 4;


const TWO: usize = 2;


const UNKNOWN_SHAPE: usize = 2;


const MANY_ELEMENTS: usize = 99_999;


const RESTIC_ELEMENT_BYTES: usize = 2;


const OVERHEAD_BYTES: usize = 200;


const KEY_BYTES: usize = 6;


const SHAPE_ELEMENT: &str = "{\"a\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},";


fn peak_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).ok_or("no VmHWM")?;
    let digits = line.split_whitespace().nth(1).ok_or("no value")?;
    Ok(digits.parse()?)
}


fn hostile_shape(index: usize) -> String {
    let body = LISTING_BYTES - OVERHEAD_BYTES;
    let elements = match index {
        0 => SHAPE_ELEMENT.repeat(MANY_ELEMENTS),
        1 => format!("{{\"paths\":[{}0]}},", "0,".repeat(body / RESTIC_ELEMENT_BYTES)),
        UNKNOWN_SHAPE => format!("{{\"zz\":\"{}\"}},", "x".repeat(body)),
        _ => format!("{{{}\"k\":0}},", "\"k\":0,".repeat(body / KEY_BYTES / TWO)),
    };
    format!("[{elements}0]")
}


#[test]
fn hostile_element_shapes_never_expand_more_than_one_element() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_bytes: LISTING_BYTES as u64,
        ..Limits::default()
    };
    let before = peak_kib()?;
    (0..SHAPES).try_for_each(|index| -> Result<(), Box<dyn Error>> {
        let shape = hostile_shape(index);
        let outcome = parse_restic(shape.as_bytes(), "repo", &limits);
        assert!(matches!(outcome, Err(BackupError::Malformed { .. })), "{outcome:?}");
        Ok(())
    })?;
    let growth = peak_kib()?.saturating_sub(before);
    assert!(growth < SHAPE_BUDGET_KIB, "peak grew by {growth} KiB");
    Ok(())
}
