//! Usage: timer_health <timers.yaml> <now-unix> <timer> <timer-show.txt> <service-show.txt>; prints the timer verdict.

use app_health::limits::DEFAULT_MAX_BYTES;
use app_health::timers::{assess_timer, load_timer_expectations, parse_service_result, parse_timer_show, service_unit};
use std::io::Write;


fn report(expectations_path: &str, now_text: &str, timer: &str, timer_path: &str, service_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expectations = load_timer_expectations(&std::fs::read_to_string(expectations_path)?, expectations_path)?;
    let expectation = expectations
        .iter()
        .find(|item| item.timer == timer)
        .ok_or("timer not in the expectations file")?;
    let timer_state = parse_timer_show(std::fs::File::open(timer_path)?, DEFAULT_MAX_BYTES, timer)?;
    let service_state = parse_service_result(std::fs::File::open(service_path)?, DEFAULT_MAX_BYTES, &service_unit(expectation))?;
    let verdict = assess_timer(expectation, &timer_state, &service_state, now_text.parse()?);
    let mut out = std::io::stdout();
    writeln!(out, "timer={timer} verdict={verdict:?} state={timer_state:?} service={service_state:?}")?;
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [expectations_path, now_text, timer, timer_path, service_path] => report(expectations_path, now_text, timer, timer_path, service_path),
        _ => Err("usage: timer_health <timers.yaml> <now-unix> <timer> <timer-show.txt> <service-show.txt>".into()),
    }
}
