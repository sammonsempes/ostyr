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


#[doc = "Outside code cannot reach the transport behind the budget.\n\n```compile_fail\nlet deps = ai_gateway::chat::production_deps();\nlet _send = deps.transport;\n```\n\n```compile_fail\nlet _url = ai_gateway::transport::ureq_transport;\n```\n\n```compile_fail\nfn read(request: &ai_gateway::model::HttpRequest) -> &str {\n    &request.url\n}\n```\n"]
pub struct NoUnbudgetedPath;
