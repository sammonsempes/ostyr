//! Parses a KEV JSON file and a decompressed EPSS CSV; usage: `kev_epss <kev.json> <epss.csv> <CVE>...`.

use std::fs::File;
use std::io::{BufReader, Write};
use vuln_match::epss::{parse_epss, EpssLimits};
use vuln_match::kev::{parse_kev, KevLimits};


const FIXED_ARGS: usize = 2;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (kev_path, epss_path) = args.first().zip(args.get(1)).ok_or("usage: kev_epss <kev.json> <epss.csv> <CVE>...")?;
    let kev = parse_kev(File::open(kev_path)?, &KevLimits::default())?;
    let epss = parse_epss(BufReader::new(File::open(epss_path)?), &EpssLimits::default())?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "kev: {} ids, bad {}, duplicates {}, declared {:?}, count_matches {}, version {:?}, released {:?}",
        kev.ids.len(),
        kev.bad_entries,
        kev.duplicates,
        kev.declared_count,
        kev.count_matches,
        kev.catalog_version,
        kev.date_released
    )?;
    writeln!(
        out,
        "epss: {} scores, bad {}, duplicates {}, model {}, date {}",
        epss.scores.len(),
        epss.bad_rows,
        epss.duplicates,
        epss.model_version,
        epss.score_date
    )?;
    args.iter()
        .skip(FIXED_ARGS)
        .try_for_each(|cve| writeln!(out, "{cve}: epss {:?}, kev {}", epss.scores.get(cve), kev.ids.contains(cve)))?;
    Ok(())
}
