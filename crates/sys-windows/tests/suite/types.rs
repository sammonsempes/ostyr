use std::error::Error;
use sys_windows::types::{Sha256Digest, SignerChain};


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Der = Vec<u8>;


pub type Pinned = Sha256Digest;


pub type TestFailure = Box<dyn Error>;


pub type GoodPair = Result<(Der, Der, Pinned), TestFailure>;


pub type OptionalChain = Result<(Option<SignerChain>, Pinned), TestFailure>;
