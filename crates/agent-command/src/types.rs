use std::error::Error;
use std::io;


pub type BoxError = Box<dyn Error + Send + Sync>;


pub type SignerFn = dyn Fn(&[u8]) -> Result<Vec<u8>, BoxError> + Send + Sync;


pub type SaveFn = dyn Fn(u64) -> io::Result<()> + Send + Sync;


pub type FillFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;
