use crate::fetch::FetchError;
use crate::query::MetricQuery;
use std::collections::BTreeMap;


pub type Timestamp = u64;


pub type Point = (Timestamp, f64);


pub type Labels = BTreeMap<String, String>;


pub type QueryParams = Vec<(String, String)>;


pub type FetchResult = Result<Vec<Point>, FetchError>;


/// Runs one query for a round; production wraps `fetch_points`, tests answer from a script.
pub type FetchFn<'a> = &'a dyn Fn(&MetricQuery) -> FetchResult;
