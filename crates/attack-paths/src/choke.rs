use crate::model::{ChokePoint, EdgeRef, Path, Recommendation};
use std::cmp::Reverse;
use std::collections::BTreeMap;


const MIN_CHOKE_PATHS: usize = 2;


const PATH_ENDS: usize = 2;


/// Nodes other than the ends crossed by two or more paths, most crossed first, ties by id.
pub fn choke_points(paths: &[Path]) -> Vec<ChokePoint> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    paths.iter().for_each(|path| {
        path.nodes
            .iter()
            .skip(1)
            .take(path.nodes.len().saturating_sub(PATH_ENDS))
            .for_each(|node| *counts.entry(node.as_str()).or_insert(0) += 1)
    });
    let mut points: Vec<ChokePoint> = counts
        .into_iter()
        .filter(|(_, crossed)| *crossed >= MIN_CHOKE_PATHS)
        .map(|(node, crossed)| ChokePoint {
            node: node.to_string(),
            paths_through: crossed,
        })
        .collect();
    points.sort_by(|left, right| {
        Reverse(left.paths_through)
            .cmp(&Reverse(right.paths_through))
            .then_with(|| left.node.cmp(&right.node))
    });
    points
}


/// Edges ranked by the number of paths that removing them closes, ties by ids.
pub fn recommendations(paths: &[Path]) -> Vec<Recommendation> {
    let mut counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    paths.iter().for_each(|path| {
        path.nodes
            .iter()
            .zip(path.nodes.iter().skip(1))
            .for_each(|(from, to)| *counts.entry((from.as_str(), to.as_str())).or_insert(0) += 1)
    });
    let mut ranked: Vec<Recommendation> = counts
        .into_iter()
        .map(|((from, to), closed)| Recommendation {
            edge: EdgeRef {
                from: from.to_string(),
                to: to.to_string(),
            },
            paths_closed: closed,
        })
        .collect();
    ranked.sort_by_key(|recommendation| Reverse(recommendation.paths_closed));
    ranked
}
