//! `usb_policy check <policy>` prints a summary; `usb_policy render <policy> <now>` prints the USBGuard rule file and its implicit target.

use device_control::parse::load_policy;
use device_control::render::{render_usbguard, summarize};
use std::io::Write;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const NOW_POSITION: usize = 2;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: usb_policy check <policy> | render <policy> <now rfc3339>";
    let command = arguments.first().ok_or(usage)?;
    let policy = load_policy(Path::new(arguments.get(1).ok_or(usage)?))?;
    let now_text = arguments.get(NOW_POSITION).map_or("1970-01-01T00:00:00Z", String::as_str);
    let now = OffsetDateTime::parse(now_text, &Rfc3339)?;
    let mut out = std::io::stdout();
    if command == "check" {
        writeln!(out, "{}", summarize(&policy, now))?;
    } else {
        let file = render_usbguard(&policy, now)?;
        write!(out, "{}", file.rules)?;
        writeln!(out, "implicit_target={:?}", file.implicit_target)?;
    }
    Ok(())
}
