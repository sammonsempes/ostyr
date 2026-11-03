use crate::catalogue::{APPROVAL_ACTION, APPROVAL_TARGET_PARAM};
use crate::model::Step;


pub const MAX_DEPTH: usize = 8;


#[derive(Debug, Clone)]
pub struct Frame<'a> {
    pub path: String,
    pub steps: &'a [Step],
    pub approved: Vec<String>,
}


#[derive(Debug, Clone)]
pub struct FlatStep<'a> {
    pub path: String,
    pub step: &'a Step,
    pub approved: Vec<String>,
}


#[derive(Debug, Clone)]
pub struct Flattened<'a> {
    pub steps: Vec<FlatStep<'a>>,
    pub truncated: bool,
}


/// The action a `request_approval` step asks approval for, when the step is one and names it literally.
pub fn approval_target(step: &Step) -> Option<String> {
    (step.connector.is_none() && step.action.as_deref() == Some(APPROVAL_ACTION))
        .then(|| step.params.get(APPROVAL_TARGET_PARAM).and_then(|value| value.as_str()).map(str::to_owned))
        .flatten()
}


/// Every step below `steps`, level by level, down to `MAX_DEPTH` levels.
pub fn descendants(steps: &[Step]) -> Vec<&Step> {
    let start: Vec<&[Step]> = vec![steps];
    let (_, found) = (0..MAX_DEPTH).fold((start, Vec::new()), |(level, mut found), _| {
        let current: Vec<&Step> = level.iter().flat_map(|group| group.iter()).collect();
        let next: Vec<&[Step]> = current
            .iter()
            .flat_map(|step| [step.then.as_slice(), step.otherwise.as_slice()])
            .collect();
        found.extend(current);
        (next, found)
    });
    found
}


pub fn approvals_in(steps: &[Step]) -> Vec<String> {
    descendants(steps).into_iter().filter_map(approval_target).collect()
}


/// One level: the steps of the frame with the approvals that gate them, and the frames of their branches.
pub fn expand<'a>(frame: &Frame<'a>) -> (Vec<FlatStep<'a>>, Vec<Frame<'a>>) {
    let mut running = frame.approved.clone();
    frame
        .steps
        .iter()
        .enumerate()
        .fold((Vec::new(), Vec::new()), |(mut flat, mut frames), (index, step)| {
            let path = format!("{}.{index}", frame.path);
            flat.push(FlatStep {
                path: path.clone(),
                step,
                approved: running.clone(),
            });
            frames.push(Frame {
                path: format!("{path}.then"),
                steps: &step.then,
                approved: [running.clone(), approvals_in(&step.otherwise)].concat(),
            });
            frames.push(Frame {
                path: format!("{path}.else"),
                steps: &step.otherwise,
                approved: [running.clone(), approvals_in(&step.then)].concat(),
            });
            running.extend(approval_target(step));
            (flat, frames)
        })
}


/// Steps in level order. A step is gated by approvals earlier in its sequence and by approvals in the opposite branch.
pub fn flatten<'a>(steps: &'a [Step], root: &str) -> Flattened<'a> {
    let start = vec![Frame {
        path: root.to_owned(),
        steps,
        approved: Vec::new(),
    }];
    let (left, found) = (0..MAX_DEPTH).fold((start, Vec::new()), |(frames, mut found), _| {
        let (flat, children): (Vec<Vec<FlatStep<'a>>>, Vec<Vec<Frame<'a>>>) = frames.iter().map(expand).unzip();
        found.extend(flat.into_iter().flatten());
        let next = children.into_iter().flatten().filter(|child| !child.steps.is_empty()).collect();
        (next, found)
    });
    Flattened {
        steps: found,
        truncated: !left.is_empty(),
    }
}
