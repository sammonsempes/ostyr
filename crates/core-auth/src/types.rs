use crate::error::AuthError;
use crate::model::{Account, Attempts, Challenge, PendingLogin, Session, StoredCredential};
use core_config::secret::SecretRef;
use openidconnect::core::CoreClient;
use openidconnect::{EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse};
use secrecy::SecretSlice;
use secrecy::SecretString;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use time::OffsetDateTime;


pub type RandomFn = fn(&mut [u8]) -> Result<(), getrandom::Error>;


pub type Clock = fn() -> OffsetDateTime;


pub type StoreKey = SecretSlice<u8>;


pub type AccountMap = BTreeMap<String, Account>;


pub type SessionMap = BTreeMap<String, Session>;


pub type AttemptMap = BTreeMap<String, Attempts>;


pub type CredentialMap = BTreeMap<String, Vec<StoredCredential>>;


pub type ChallengeMap = BTreeMap<String, Challenge>;


pub type RoleSet = BTreeSet<String>;


pub type RoleCatalog = BTreeMap<String, BTreeSet<String>>;


pub type CompromisedSet = HashSet<String>;


pub type VerifyFn<'a> = &'a dyn Fn(&str, &str) -> Result<bool, AuthError>;


pub type Parameters = Vec<(&'static str, String)>;


pub type PendingMap = BTreeMap<String, PendingLogin>;


pub type GroupRoleMap = BTreeMap<String, BTreeSet<String>>;


pub type HttpFn<'a> = &'a dyn Fn(HttpRequest) -> Result<HttpResponse, io::Error>;


pub type ResolveFn<'a> = &'a dyn Fn(&SecretRef) -> Result<SecretString, io::Error>;


pub type OidcClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;
