use crate::error::ExportError;
use core_config::secret::SecretRef;
use rustls::{ClientConnection, StreamOwned};
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;


pub type BoxError = Box<dyn Error + Send + Sync>;


pub type LabelMap = BTreeMap<String, String>;


pub type PostFn<'a> = dyn FnMut(&str) -> Result<(), BoxError> + 'a;


pub type DeliverFn<'a> = dyn FnMut(&str) -> Result<(), ExportError> + 'a;


pub type SleepFn<'a> = dyn FnMut(Duration) + 'a;


pub type ResolveFn<'a> = dyn Fn(&SecretRef) -> Result<String, BoxError> + 'a;


pub type OpenFn<'a> = dyn FnMut(&Path) -> io::Result<Box<dyn Write>> + 'a;


pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;


pub type SyncFn<'a> = dyn FnMut(&Path) -> io::Result<()> + 'a;
