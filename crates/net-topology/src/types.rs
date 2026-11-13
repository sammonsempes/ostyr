use crate::model::NeighbourId;
use serde_json::value::RawValue;


pub type LinkKey = (String, String, NeighbourId, NeighbourId);


pub type PortKey = (String, String);


pub type RawList<'a> = Vec<&'a RawValue>;


pub type AnyError = Box<dyn std::error::Error + Send + Sync>;
