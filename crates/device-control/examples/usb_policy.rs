//! `check <policy> <now>` prints a summary, `render <policy> <now>` the USBGuard rule file, `evaluate <policy> <now> <vendor> <product> <classes>` a decision.

use device_control::evaluate::{class_only_allows, evaluate, next_change};
use device_control::model::UsbDevice;
use device_control::parse::load_policy;
use device_control::render::{render_usbguard, summarize};
use std::io::Write;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str =
    "usage: usb_policy check <policy> <now> | render <policy> <now> | evaluate <policy> <now> <vendor> <product> <classes,comma,separated>";


const POLICY_POSITION: usize = 1;


const NOW_POSITION: usize = 2;


const VENDOR_POSITION: usize = 3;


const PRODUCT_POSITION: usize = 4;


const CLASSES_POSITION: usize = 5;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let argument = |position: usize| arguments.get(position).ok_or(USAGE);
    let command = argument(0)?;
    let policy = load_policy(Path::new(argument(POLICY_POSITION)?))?;
    let now = OffsetDateTime::parse(argument(NOW_POSITION)?, &Rfc3339)?;
    let mut out = std::io::stdout();
    match command.as_str() {
        "check" => {
            writeln!(out, "{} next_change={:?}", summarize(&policy, now), next_change(&policy, now))?;
            class_only_allows(&policy)
                .iter()
                .try_for_each(|index| writeln!(out, "warning: rule {index} allows a class alone and no block rule covers class 08"))?;
        }
        "render" => {
            let file = render_usbguard(&policy, now)?;
            write!(out, "{}", file.rules)?;
            writeln!(out, "implicit_target={:?}", file.implicit_target)?;
        }
        "evaluate" => {
            let interfaces = argument(CLASSES_POSITION)?
                .split(',')
                .filter(|class| !class.is_empty())
                .map(|class| (class.to_string(), "00".to_string(), "00".to_string()))
                .collect();
            let device = UsbDevice {
                vendor: argument(VENDOR_POSITION)?.clone(),
                product: argument(PRODUCT_POSITION)?.clone(),
                serial: None,
                interfaces,
            };
            writeln!(out, "{:?}", evaluate(&policy, &device, now))?;
        }
        _ => Err(USAGE)?,
    }
    Ok(())
}
