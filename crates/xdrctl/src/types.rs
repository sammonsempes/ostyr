use crate::error::ClientError;
use crate::model::{HttpReply, HttpRequest};
use std::path::Path;


pub type SendFn<'a> = dyn Fn(Option<&Path>, &HttpRequest) -> Result<HttpReply, ClientError> + 'a;
