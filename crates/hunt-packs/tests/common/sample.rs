use hunt_packs::model::{Baseline, Cost, HuntPack, Source};
use metric_alerts::fetch::FetchSettings;
use std::error::Error;


pub const NOW: u64 = 1_700_000_000;


pub const WINDOW: u64 = 86_400;


pub const ROWS: u64 = 1_000;


pub const SECONDS: u64 = 10;


pub const BYTES: u64 = 1_000_000;


pub const TIMEOUT_MS: u64 = 10_000;


pub const PASSWORD: &str = "HUNTPW-7d1e";


pub const QUERY: &str =
    "SELECT 1 FROM events WHERE tenant = {tenant:String} AND ts BETWEEN {window_start:DateTime64(3)} AND {window_end:DateTime64(3)};";


pub fn pack() -> HuntPack {
    HuntPack {
        id: "sample".to_string(),
        title: "Sample".to_string(),
        hypothesis: "A sample".to_string(),
        technique: "T1059".to_string(),
        source: Source::Clickhouse,
        query: QUERY.to_string(),
        schedule_seconds: WINDOW,
        window_seconds: WINDOW,
        cost: Cost {
            max_rows: ROWS,
            max_seconds: SECONDS,
            max_bytes_read: Some(BYTES),
        },
        baseline: Baseline { max_matches: 0 },
        tests: Vec::new(),
    }
}


pub fn settings(port: u16) -> FetchSettings {
    FetchSettings {
        url: format!("http://127.0.0.1:{port}"),
        user: "ostyr".to_string(),
        password_file: "unused".into(),
        ca_file: None,
        timeout_ms: TIMEOUT_MS,
    }
}


const HEX_RADIX: u32 = 16;


const ESCAPE_DIGITS: usize = 2;


fn percent_decode(text: &str) -> Result<String, Box<dyn Error>> {
    let mut parts = text.split('%');
    let head = parts.next().unwrap_or("").as_bytes().to_vec();
    let bytes = parts.try_fold(head, |mut decoded, part| {
        decoded.push(u8::from_str_radix(part.get(..ESCAPE_DIGITS).ok_or("short escape")?, HEX_RADIX)?);
        decoded.extend_from_slice(part.get(ESCAPE_DIGITS..).unwrap_or("").as_bytes());
        Ok::<_, Box<dyn Error>>(decoded)
    })?;
    Ok(String::from_utf8(bytes)?)
}


pub fn sent_params(request: &str) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("no request line")?;
    let query_text = target.strip_prefix("/?").ok_or("no query")?;
    query_text
        .split('&')
        .map(|pair| {
            let (name, value) = pair.split_once('=').ok_or("no equals")?;
            Ok((percent_decode(&name.replace('+', " "))?, percent_decode(&value.replace('+', " "))?))
        })
        .collect()
}


pub fn param(request: &str, name: &str) -> Result<String, Box<dyn Error>> {
    sent_params(request)?
        .into_iter()
        .find(|(found, _)| found == name)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("no parameter {name}").into())
}
