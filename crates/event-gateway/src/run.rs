use crate::error::GatewayError;
use crate::model::{GatewayFile, AUDIT_TENANT, MODULE, RELOAD_REQUEST_ID};
use crate::publish::gateway_sink;
use crate::session::new_gateway;
use crate::settings::open_settings;
use agent_channel::app::{alerting_audit, debounce, keep_signals, reload_context, shared_log_audit};
use agent_channel::server_app::{run_server, ServerFile};
use agent_channel::types::ShutdownSignal;
use core_audit::log::open_file_log;
use core_config::load::load_file;
use core_config::watch::watch_files;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;


pub fn load_gateway_file(path: &Path) -> Result<GatewayFile, GatewayError> {
    Ok(load_file::<GatewayFile>(path)?)
}


/// Serves the agent channel with the JetStream sink until `shutdown`; the gateway settings reload on file change and on `SIGHUP`, each audited.
pub async fn run_gateway(server: ServerFile, gateway: GatewayFile, listener: TcpListener, shutdown: ShutdownSignal) -> Result<(), GatewayError> {
    let log = Arc::new(open_file_log(&gateway.audit_file)?);
    let engine = Arc::new(open_settings(
        gateway.settings_file.clone(),
        alerting_audit(shared_log_audit(&log)),
        reload_context(&gateway.settings_file, MODULE, AUDIT_TENANT, RELOAD_REQUEST_ID),
    )?);
    let _watch = watch_files(Arc::clone(&engine), std::slice::from_ref(&gateway.settings_file), debounce())?;
    let _signals = keep_signals(Arc::clone(&engine))?;
    let sink = gateway_sink(Arc::new(new_gateway(engine)));
    Ok(run_server(server, listener, shutdown, sink).await?)
}
