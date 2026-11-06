use crate::model::Step;


pub const MAX_DEPTH: usize = 8;


#[derive(Debug, Clone)]
pub struct Frame<'a> {
    pub path: String,
    pub steps: &'a [Step],
}


#[derive(Debug, Clone)]
pub struct FlatStep<'a> {
    pub path: String,
    pub step: &'a Step,
}


#[derive(Debug, Clone)]
pub struct Flattened<'a> {
    pub steps: Vec<FlatStep<'a>>,
    pub truncated: bool,
}


/// One level: the steps of the frame and the frames of their branches.
pub fn expand<'a>(frame: &Frame<'a>) -> (Vec<FlatStep<'a>>, Vec<Frame<'a>>) {
    frame
        .steps
        .iter()
        .enumerate()
        .fold((Vec::new(), Vec::new()), |(mut flat, mut frames), (index, step)| {
            let path = format!("{}.{index}", frame.path);
            frames.push(Frame {
                path: format!("{path}.then"),
                steps: &step.then,
            });
            frames.push(Frame {
                path: format!("{path}.else"),
                steps: &step.otherwise,
            });
            flat.push(FlatStep { path, step });
            (flat, frames)
        })
}


/// Steps in level order, down to `MAX_DEPTH` levels.
pub fn flatten<'a>(steps: &'a [Step], root: &str) -> Flattened<'a> {
    let start = vec![Frame {
        path: root.to_owned(),
        steps,
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
