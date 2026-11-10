use crate::types::TestResult;
use agent_channel::spool::append_back;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::sync::Barrier;
use std::thread::scope;
use tempfile::tempdir;


const WRITERS: usize = 2;


const LINES_PER_WRITER: usize = 400;


const LINE_BYTES: usize = 3_000;


const CALL_LINES: usize = 3;


fn payload(writer: usize, index: usize) -> String {
    format!("{writer}-{index}-{}", "x".repeat(LINE_BYTES))
}


#[test]
fn concurrent_appends_to_one_spool_never_interleave() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let barrier = Barrier::new(WRITERS);
    let outcomes = scope(|workers| {
        (0..WRITERS)
            .map(|writer| {
                let (spool_ref, barrier_ref) = (&spool, &barrier);
                workers.spawn(move || {
                    barrier_ref.wait();
                    (0..LINES_PER_WRITER).try_for_each(|index| append_back(std::iter::once(Ok(payload(writer, index))), spool_ref).map(|_| ()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "a writer panicked"))
            .collect::<Vec<_>>()
    });
    outcomes
        .into_iter()
        .try_for_each(|outcome| outcome?.map_err(Box::<dyn std::error::Error>::from))?;
    let text = fs::read_to_string(&spool)?;
    let found: BTreeSet<&str> = text.lines().collect();
    let expected: Vec<String> = (0..WRITERS)
        .flat_map(|writer| (0..LINES_PER_WRITER).map(move |index| payload(writer, index)))
        .collect();
    assert_eq!(text.lines().count(), WRITERS * LINES_PER_WRITER);
    assert_eq!(found.len(), WRITERS * LINES_PER_WRITER);
    assert!(expected.iter().all(|line| found.contains(line.as_str())));
    Ok(())
}


#[test]
fn a_failing_line_appends_nothing_of_the_call() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let lines = vec![Ok("whole".to_owned()), Err(io::Error::other("injected"))];
    assert!(append_back(lines.into_iter(), &spool).is_err());
    assert!(!spool.exists());
    let batch = (0..CALL_LINES).map(|index| Ok(index.to_string()));
    assert!(append_back(batch, &spool)?);
    assert_eq!(fs::read_to_string(&spool)?, "0\n1\n2\n");
    Ok(())
}
