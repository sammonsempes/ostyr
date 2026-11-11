use axum::Router;
use core_api::types::{AccessTable, SharedState};
use core_pg::migrate::Migration;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub type MigrationPlan = Vec<(&'static str, &'static [Migration])>;


pub type Parts = (Router<SharedState>, AccessTable, Vec<OpenApiDocument>);
