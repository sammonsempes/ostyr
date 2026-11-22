use agent_channel::model::Identity;
use agent_channel::proto::ShellFrame;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tonic::Status;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Received = Vec<Result<ShellFrame, Status>>;


pub type Stored = Arc<Mutex<Vec<(Identity, u64)>>>;
