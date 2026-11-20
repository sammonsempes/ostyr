use crate::model::{DATA_CUT_BYTES, ENTITY_LOOKBACK};


const DATA_CLOSE: &str = "</Data>";


const DATA_OPEN: &str = "<Data";


pub fn cut_value(value: &str) -> String {
    if value.len() > DATA_CUT_BYTES {
        let end = (0..=DATA_CUT_BYTES).rev().find(|at| value.is_char_boundary(*at)).unwrap_or(0);
        let head = value.split_at(end).0;
        let kept = head
            .rfind('&')
            .filter(|amp| end - amp <= ENTITY_LOOKBACK && !head.split_at(*amp).1.contains(';'))
            .unwrap_or(end);
        let omitted = value.len() - kept;
        format!("{}[cut, {omitted} bytes]", value.split_at(kept).0)
    } else {
        value.to_string()
    }
}


pub fn cut_segment(segment: &str) -> String {
    segment
        .rfind(DATA_OPEN)
        .and_then(|at| segment.split_at(at).1.find('>').map(|close| at + close + 1))
        .map_or_else(
            || segment.to_string(),
            |value_start| {
                let (open, value) = segment.split_at(value_start);
                format!("{open}{}", cut_value(value))
            },
        )
}


pub fn cut_data_values(text: &str) -> String {
    let segments: Vec<&str> = text.split(DATA_CLOSE).collect();
    let count = segments.len();
    segments
        .iter()
        .enumerate()
        .map(|(position, segment)| {
            if position + 1 < count {
                cut_segment(segment)
            } else {
                (*segment).to_string()
            }
        })
        .collect::<Vec<String>>()
        .join(DATA_CLOSE)
}
