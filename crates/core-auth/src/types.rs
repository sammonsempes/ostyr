use crate::error::AuthError;
use crate::model::{Account, Attempts, Session};
use secrecy::SecretSlice;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use time::OffsetDateTime;


pub type RandomFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;


pub type Clock = fn() -> OffsetDateTime;


pub type StoreKey = SecretSlice<u8>;


pub type AccountMap = BTreeMap<String, Account>;


pub type SessionMap = BTreeMap<String, Session>;


pub type AttemptMap = BTreeMap<String, Attempts>;


pub type RoleSet = BTreeSet<String>;


pub type RoleCatalog = BTreeMap<String, BTreeSet<String>>;


pub type CompromisedSet = HashSet<String>;


pub type VerifyFn<'a> = &'a dyn Fn(&str, &str) -> Result<bool, AuthError>;


pub type Parameters = Vec<(&'static str, String)>;
