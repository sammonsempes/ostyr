use chrono::Utc;
use oncall::link::{issue_link, redeem_link, LinkAction, Nonce};
use oncall::linkkey::read_link_key;
use std::collections::HashSet;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const USAGE: &str = "usage: oncall_link <key-file>";


const ALERT: i64 = 42;


const KEY_ARG: usize = 1;


const EXTRA_ARG: usize = 2;


fn show<Value: std::fmt::Debug>(out: &mut impl Write, label: &str, value: Value) -> std::io::Result<()> {
    writeln!(out, "{label}: {value:?}")
}


fn run(key_file: &Path) -> Result<(), Box<dyn Error>> {
    let key = read_link_key(key_file)?;
    let now = Utc::now();
    let mut out = stdout();
    let mut seen: HashSet<Nonce> = HashSet::new();
    let mut used = |nonce: &Nonce| Ok::<bool, std::io::Error>(seen.insert(*nonce));
    let token = issue_link(ALERT, LinkAction::Acknowledge, "acme", now, &key)?;
    show(&mut out, "issued length", token.len())?;
    let first = redeem_link(&token, now, &key, &mut used).map(|claims| (claims.tenant, claims.alert, claims.action));
    show(&mut out, "first redeem", first)?;
    let replay = redeem_link(&token, now, &key, &mut used).map(|claims| claims.alert);
    show(&mut out, "replay", replay.map_err(|error| error.to_string()))?;
    let flipped: String = token.chars().rev().collect();
    let tampered = redeem_link(&flipped, now, &key, &mut used).map(|claims| claims.alert);
    show(&mut out, "tampered", tampered.map_err(|error| error.to_string()))?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(KEY_ARG), args.get(EXTRA_ARG)) {
        (Some(path), None) => run(Path::new(path)),
        _ => Err(USAGE.into()),
    }
}
