use std::io;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum RunError {
    #[error("cannot start the log tool")]
    Spawn(#[source] io::Error),
    #[error("cannot wait for the log tool")]
    Wait(#[source] io::Error),
    #[error("cannot stop the log tool")]
    Kill(#[source] io::Error),
    #[error("the output reader failed")]
    Reader,
    #[error("cannot create the output pipe")]
    Pipe(#[source] io::Error),
}


#[derive(Debug, Error)]
pub enum PollError {
    #[error("running the log tool failed")]
    Run(#[from] RunError),
    #[error("cursor file write failed")]
    Cursor(#[source] io::Error),
    #[error("cursor file read failed")]
    CursorRead(#[source] io::Error),
    #[error("spool append failed")]
    Spool(#[source] io::Error),
}
