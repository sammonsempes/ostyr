use dns_rpz::model::CommandStatus;
use std::io;
use std::time::Duration;


pub fn succeeding_runner(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Ok(CommandStatus::Success)
}


pub fn failing_runner(_program: &str, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Ok(CommandStatus::Failed(Some(1)))
}
