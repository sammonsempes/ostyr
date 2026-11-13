use crate::measure::assemble;
use crate::memory_support::framed;
use crate::memory_support::{POINTS, RESOURCE, VALUE};


const KEY: u8 = 0x0a;


const POINT_ATTRIBUTES: u8 = 0x3a;


const NUMBER_VALUE: u8 = 0x31;


const POINT_VALUE: i64 = 1;


const DOUBLE_VALUE: u8 = 0x21;


const SCOPE: u8 = 0x0a;


const SCOPE_ATTRIBUTE: u8 = 0x1a;


const DIGITS: usize = 9;


const EXPONENTS: usize = 11;


const LONGEST_EXPONENT: usize = 254;


const MIXED_LABELS: usize = 4;


pub fn digit_pairs(label: usize, key_width: usize) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let key = format!("{label:0>width$}", width = key_width);
    (1..=DIGITS)
        .map(|digit| {
            let number = format!("{digit}e-{}", LONGEST_EXPONENT - label % EXPONENTS).parse::<f64>()?;
            let any = [DOUBLE_VALUE].into_iter().chain(number.to_le_bytes()).collect::<Vec<u8>>();
            Ok(framed(POINT_ATTRIBUTES, &[framed(KEY, key.as_bytes()), framed(VALUE, &any)].concat()))
        })
        .collect()
}


pub fn request_distinct(
    points: usize,
    count: usize,
    key_width: usize,
    filler_scope_attributes: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = [NUMBER_VALUE].into_iter().chain(POINT_VALUE.to_le_bytes()).collect::<Vec<u8>>();
    let table = (0..count).map(|label| digit_pairs(label, key_width)).collect::<Result<Vec<_>, _>>()?;
    let point = |index: usize| {
        let pairs = table.iter().enumerate().flat_map(|(label, row)| {
            let digit = if label < MIXED_LABELS {
                index / DIGITS.pow(label as u32) % DIGITS
            } else {
                0
            };
            row.get(digit).into_iter().flatten().copied()
        });
        framed(POINTS, &[pairs.collect::<Vec<u8>>(), value.clone()].concat())
    };
    let filler = framed(SCOPE_ATTRIBUTE, &framed(KEY, b"k")).repeat(filler_scope_attributes);
    Ok(assemble(points, &framed(RESOURCE, &[]), &framed(SCOPE, &filler), point))
}
