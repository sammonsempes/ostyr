//! Usage: `ad_paths <snapshot.json> [tags.yaml]`: users and workstations are the entry points; critical nodes are domain controllers and the tags.
use ad_posture::limits::Limits as SnapshotLimits;
use ad_posture::snapshot::read_snapshot;
use attack_paths::ad::{apply_ad_tags, graph_from_snapshot};
use attack_paths::model::{Limits, NodeKind, Tags, MAX_DEPTH, MAX_PATHS};
use attack_paths::paths::paths_to_critical;
use attack_paths::report::write_report;
use attack_paths::tags::load_tags;
use std::error::Error;
use std::fs::File;
use std::io::stdout;
use std::path::Path;


const SNAPSHOT_ARGUMENT: usize = 1;


const TAGS_ARGUMENT: usize = 2;


const SHOWN_POINTS: usize = 10;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    let snapshot = read_snapshot(
        File::open(arguments.get(SNAPSHOT_ARGUMENT).ok_or("missing snapshot.json")?)?,
        &SnapshotLimits::default(),
    )?;
    let mut built = graph_from_snapshot(&snapshot);
    built
        .graph
        .nodes
        .iter_mut()
        .for_each(|node| node.entry_point = matches!(node.kind, NodeKind::User | NodeKind::Workstation));
    let tags = match arguments.get(TAGS_ARGUMENT) {
        Some(path) => load_tags(Path::new(path))?,
        None => Tags::default(),
    };
    let skipped_tags = apply_ad_tags(&mut built, &tags)?;
    let found = paths_to_critical(
        &built.graph,
        Limits {
            max_depth: MAX_DEPTH,
            max_paths: MAX_PATHS,
        },
    )?;
    write_report(&mut stdout(), &built, &found, &skipped_tags, SHOWN_POINTS)?;
    Ok(())
}
