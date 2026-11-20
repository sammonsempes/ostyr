//! The only way the platform reaches a language model: bounded request, bounded answer, telemetry sent as tagged data.

pub mod budget;
pub mod chat;
pub mod error;
pub mod limits;
pub mod model;
pub mod pg;
pub mod request;
pub mod response;
pub mod settings;
pub mod transport;
pub mod types;


#[doc = "Outside code cannot reach the transport, the key or the URL behind the budget.\n\n```compile_fail\nlet deps = ai_gateway::chat::production_deps();\nlet _send = deps.transport;\n```\n\n```compile_fail\nlet _url = ai_gateway::transport::ureq_transport;\n```\n\n```compile_fail\nfn read(request: &ai_gateway::model::HttpRequest) -> &str {\n    &request.url\n}\n```\n\n```compile_fail\nuse ai_gateway::budget::{BudgetDeps, Gate, Stores};\nfn bypass<'a>(budget: ai_gateway::types::BudgetExecutor<'a, 'a>, alerts: alerts::types::Executor<'a, 'a>, gate: &'a Gate) {\n    let stores = Stores { budget, alerts, gate };\n    let deps = BudgetDeps { chat: ai_gateway::chat::production_deps(), wall_clock: || 0 };\n    let _both = (stores, deps);\n}\n```\n\n```compile_fail\nlet _key = ai_gateway::request::read_authorization(std::path::Path::new(\"key\"));\n```\n\n```compile_fail\nlet _key = ai_gateway::request::read_key;\n```\n\n```compile_fail\nlet _key = ai_gateway::request::key_text;\n```\n\n```compile_fail\nlet _url = ai_gateway::settings::endpoint_url;\n```\n\n```compile_fail\nlet _key = ai_gateway::model::request_authorization;\n```\n"]
pub struct NoUnbudgetedPath;
