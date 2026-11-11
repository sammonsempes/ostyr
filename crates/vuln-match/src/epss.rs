//! FIRST EPSS daily CSV parser (already decompressed: gzip is the caller's concern).

use crate::error::EpssError;
use crate::limits::{
    EPSS_DATE_KEY, EPSS_HEADER, EPSS_META_PREFIX, EPSS_MODEL_KEY, MAX_CATALOGUE_TEXT_CHARS, MAX_EPSS_BYTES, MAX_EPSS_LINE_BYTES, MAX_EPSS_ROWS,
};
use crate::text::{bounded_text, is_cve_id};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::iter::from_fn;


const META_LINE: usize = 0;


const HEADER_LINE: usize = 1;


const SCORE_MIN: f64 = 0.0;


const SCORE_MAX: f64 = 1.0;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpssLimits {
    pub max_bytes: u64,
    pub max_rows: usize,
    pub max_line_bytes: usize,
    pub max_text_chars: usize,
}


impl Default for EpssLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_EPSS_BYTES,
            max_rows: MAX_EPSS_ROWS,
            max_line_bytes: MAX_EPSS_LINE_BYTES,
            max_text_chars: MAX_CATALOGUE_TEXT_CHARS,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Default)]
pub struct EpssScores {
    pub scores: BTreeMap<String, f64>,
    pub model_version: String,
    pub score_date: String,
    pub bad_rows: usize,
    pub duplicates: usize,
}


fn next_line<Source: BufRead>(source: &mut Source, total: &mut u64, line: usize, limits: &EpssLimits) -> Result<Option<String>, EpssError> {
    let mut buffer = Vec::new();
    let read = source.by_ref().take(limits.max_line_bytes as u64 + 1).read_until(b'\n', &mut buffer)?;
    *total += read as u64;
    if *total > limits.max_bytes {
        Err(EpssError::TooLarge { max: limits.max_bytes })?;
    }
    if buffer.len() > limits.max_line_bytes {
        Err(EpssError::LineTooLong {
            line,
            max: limits.max_line_bytes,
        })?;
    }
    Ok((read > 0).then(|| String::from_utf8_lossy(&buffer).trim_end_matches(['\r', '\n']).to_string()))
}


fn meta_value<'text>(body: &'text str, key: &str) -> Option<&'text str> {
    body.split(',')
        .find_map(|pair| pair.split_once(':').filter(|(name, _)| *name == key).map(|(_, value)| value))
}


fn unit_interval(text: &str) -> Option<f64> {
    text.parse::<f64>().ok().filter(|value| (SCORE_MIN..=SCORE_MAX).contains(value))
}


fn parse_row(line: &str) -> Option<(String, f64)> {
    match line.split(',').collect::<Vec<&str>>().as_slice() {
        [cve, epss, percentile] if is_cve_id(cve) => unit_interval(percentile).and(unit_interval(epss)).map(|score| (cve.to_string(), score)),
        _ => None,
    }
}


/// Reads the daily CSV under byte, row and line caps; the first of duplicate rows wins, a row with a bad id or value is counted and dropped.
pub fn parse_epss<Source: BufRead>(mut source: Source, limits: &EpssLimits) -> Result<EpssScores, EpssError> {
    let mut total = 0;
    let mut line_number = 0;
    let lines = from_fn(|| {
        line_number += 1;
        next_line(&mut source, &mut total, line_number, limits).transpose()
    });
    let mut scores = EpssScores::default();
    let mut meta = None;
    let mut header_seen = false;
    lines.enumerate().try_for_each(|(index, line)| -> Result<(), EpssError> {
        let text = line?;
        match index {
            META_LINE => {
                meta = text.strip_prefix(EPSS_META_PREFIX).and_then(|body| {
                    meta_value(body, EPSS_MODEL_KEY)
                        .zip(meta_value(body, EPSS_DATE_KEY))
                        .map(|(model, date)| (bounded_text(model, limits.max_text_chars), bounded_text(date, limits.max_text_chars)))
                });
                if meta.is_none() {
                    Err(EpssError::BadMeta)?;
                }
            }
            HEADER_LINE => {
                header_seen = text == EPSS_HEADER;
                if !header_seen {
                    Err(EpssError::BadHeader)?;
                }
            }
            _ if index - HEADER_LINE > limits.max_rows => Err(EpssError::TooMany { max: limits.max_rows })?,
            _ => match parse_row(&text) {
                None => scores.bad_rows += 1,
                Some((cve, score)) => match scores.scores.entry(cve) {
                    Entry::Occupied(_) => scores.duplicates += 1,
                    Entry::Vacant(slot) => {
                        slot.insert(score);
                    }
                },
            },
        }
        Ok(())
    })?;
    let (model_version, score_date) = meta.ok_or(EpssError::BadMeta)?;
    if !header_seen {
        Err(EpssError::BadHeader)?;
    }
    Ok(EpssScores {
        model_version,
        score_date,
        ..scores
    })
}
