use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::Page;
use crate::service::ServiceSettings;
use core_config::error::ConfigError;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;


pub type BorrowedLabels<'a> = BTreeMap<Cow<'a, str>, Cow<'a, str>>;


pub type LabelsAndExtra<'a> = (BorrowedLabels<'a>, usize);


pub type PageParser<Item> = fn(&[u8], &Limits, usize) -> Result<Page<Item>, ParseError>;


pub type InterruptWait = Pin<Box<dyn Future<Output = io::Result<()>>>>;


/// The sleep between two rounds.
pub type WaitFn = fn(Duration) -> Pin<Box<dyn Future<Output = ()>>>;


/// The one start read of the service settings file; production passes `load_service_settings`.
pub type StartRead = fn(&Path) -> Result<ServiceSettings, ConfigError>;


/// Stops one reload source (the file watch or the signal thread) and waits for it to end.
pub type Stopper = Box<dyn FnOnce()>;


/// The reload signals, registered first in `main`.
#[cfg(unix)]
pub type ReloadSignals = signal_hook::iterator::Signals;


#[cfg(not(unix))]
#[derive(Debug)]
pub struct ReloadSignals;
