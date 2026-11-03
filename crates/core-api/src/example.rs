use crate::model::{Requirement, Rule};
use crate::types::{AccessTable, SharedState};
use axum::routing::get;
use axum::Router;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const PING_REPLY: &str = "pong";


pub const PING_PERMISSION: &str = "events.read";


#[derive(OpenApi)]
#[openapi(paths(ping))]
pub struct ExampleDoc;


#[utoipa::path(
    get,
    path = "/example/ping",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A fixed reply", body = String),
        (status = 401, description = "No valid session"),
        (status = 403, description = "Permission denied")
    )
)]
pub async fn ping() -> &'static str {
    PING_REPLY
}


pub fn example_router() -> Router<SharedState> {
    Router::new().route("/example/ping", get(ping))
}


pub fn example_access() -> AccessTable {
    [(
        "GET /example/ping".to_owned(),
        Rule {
            requirement: Requirement::Permission(PING_PERMISSION.to_owned()),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


pub fn example_document() -> OpenApiDocument {
    ExampleDoc::openapi()
}
