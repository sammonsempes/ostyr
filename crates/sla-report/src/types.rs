use crate::model::{Period, SlaFigure};


pub type FiguresError = Box<dyn std::error::Error + Send + Sync>;


pub type FiguresFn<'a> = dyn Fn(&str, &Period) -> Result<SlaFigure, FiguresError> + 'a;


pub type FiguresByService = std::collections::BTreeMap<String, std::collections::BTreeMap<String, SlaFigure>>;
