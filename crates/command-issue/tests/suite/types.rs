use agent_command::model::TrustedKey;
use std::error::Error;
use std::path::Path;


pub type Hook = dyn Fn() + Send + Sync;


pub type KeyChange = Box<dyn Fn(&mut TrustedKey)>;


pub type Plant = Box<dyn Fn(&Path) -> Result<(), Box<dyn Error>>>;
