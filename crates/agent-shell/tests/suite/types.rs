use agent_channel::types::{ShellReader, ShellWriter};
use std::error::Error;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Calls = Arc<Mutex<Vec<&'static str>>>;


pub type Handover = Arc<Mutex<Option<oneshot::Sender<(ShellReader, ShellWriter)>>>>;
