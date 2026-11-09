use crate::model::REDACTION_MARK;
use regex::bytes::Regex;


/// Redacts every non-empty match of every pattern, all found on the original bytes.
pub fn redact(bytes: Vec<u8>, patterns: &[Regex]) -> Vec<u8> {
    redact_capped(&bytes, patterns, bytes.len(), usize::MAX).0
}


/// Marks the bytes covered by a match starting before `boundary`, on the original text only, so overlapping patterns never leak and marks are never rewritten.
pub fn covered_bytes(bytes: &[u8], patterns: &[Regex], boundary: usize) -> Vec<bool> {
    let mut covered = vec![false; bytes.len()];
    patterns.iter().for_each(|pattern| {
        pattern
            .find_iter(bytes)
            .take_while(|found| found.start() < boundary)
            .filter(|found| !found.is_empty())
            .for_each(|found| covered.get_mut(found.range()).into_iter().for_each(|span| span.fill(true)));
    });
    covered
}


/// One pass: each covered run becomes one mark, the output stops at `cap`; returns it and the original bytes it accounts for.
pub fn render(bytes: &[u8], covered: &[bool], cap: usize) -> (Vec<u8>, usize) {
    covered
        .chunk_by(|left, right| left == right)
        .scan((0, 0), |(offset, produced), run| {
            let start = *offset;
            *offset += run.len();
            let masked = run.contains(&true);
            let full: &[u8] = if masked {
                REDACTION_MARK
            } else {
                bytes.get(start..*offset).unwrap_or(&[])
            };
            let room = cap.saturating_sub(*produced);
            let piece = full.get(..room.min(full.len())).unwrap_or(&[]);
            *produced += piece.len();
            let end = if masked { *offset } else { start + piece.len() };
            (room > 0).then_some((piece, end))
        })
        .fold((Vec::new(), 0), |(mut output, _), (piece, end)| {
            output.extend(piece);
            (output, end)
        })
}


/// Only matches starting before `boundary` are replaced (the text beyond is context); a match straddling it is replaced whole.
pub fn redact_capped(bytes: &[u8], patterns: &[Regex], boundary: usize, cap: usize) -> (Vec<u8>, usize) {
    let covered = covered_bytes(bytes, patterns, boundary);
    let inside = boundary.checked_sub(1).and_then(|before| covered.get(before)).copied().unwrap_or(false);
    let extension = if inside {
        covered.get(boundary..).into_iter().flatten().take_while(|flag| **flag).count()
    } else {
        0
    };
    let split = boundary + extension;
    render(bytes.get(..split).unwrap_or(bytes), covered.get(..split).unwrap_or(&covered), cap)
}
