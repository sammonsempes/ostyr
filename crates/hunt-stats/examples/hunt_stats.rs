//! Usage: `hunt_stats stack <csv> [max_entities]` (entity,key per line) or `hunt_stats beacon <file>` (one timestamp per line).
use hunt_stats::beacon::beaconing;
use hunt_stats::input::{parse_observations, parse_timestamps, read_bounded};
use hunt_stats::model::{BeaconLimits, StackLimits};
use hunt_stats::render::{write_beacon, write_key_report};
use hunt_stats::stack::rare_keys;
use std::error::Error;
use std::fs::File;
use std::io::stdout;


const MAX_INPUT_BYTES: u64 = 67_108_864;


const MAX_ENTITIES_ARGUMENT: usize = 2;


const DEFAULT_MAX_ENTITIES: usize = 3;


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match (arguments.first().map(String::as_str), arguments.get(1)) {
        (Some("stack"), Some(path)) => {
            let max_entities = arguments
                .get(MAX_ENTITIES_ARGUMENT)
                .map_or(Ok(DEFAULT_MAX_ENTITIES), |text| text.parse())?;
            let rows = parse_observations(&read_bounded(&mut File::open(path)?, MAX_INPUT_BYTES)?)?;
            write_key_report(&rare_keys(&rows, max_entities, &StackLimits::default())?, &mut stdout())?;
            Ok(())
        }
        (Some("beacon"), Some(path)) => {
            let times = parse_timestamps(&read_bounded(&mut File::open(path)?, MAX_INPUT_BYTES)?)?;
            write_beacon(beaconing(&times, &BeaconLimits::default())?.as_ref(), &mut stdout())?;
            Ok(())
        }
        _ => Err("usage: hunt_stats stack <csv> [max_entities] | hunt_stats beacon <file>".into()),
    }
}
