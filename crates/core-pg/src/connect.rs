use crate::error::{reduce, PgError};
use crate::password::read_password;
use crate::settings::PgSettings;
use crate::tls::client_config;
use crate::types::TlsConnection;
use core_config::reload::{current_config, ReloadEngine};
use std::path::Path;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::warn;


/// `SslMode::Require` makes the client refuse a server without TLS; the rustls verifier checks the chain and the host name.
pub fn pg_config(settings: &PgSettings, password: &[u8]) -> Config {
    let mut config = Config::new();
    config
        .host(&settings.host)
        .port(settings.port)
        .dbname(&settings.database)
        .user(&settings.user)
        .password(password)
        .ssl_mode(SslMode::Require)
        .connect_timeout(Duration::from_secs(settings.connect_timeout_secs));
    config
}


/// Runs the connection until the client is dropped or the server closes it.
pub async fn drive(connection: TlsConnection) {
    if let Err(error) = connection.await {
        let reduced = reduce(error);
        warn!(%reduced, "database connection ended");
    }
}


/// One settings snapshot, the password read afresh from its file, TLS with verification always on, the whole connect under a deadline.
pub async fn connect_with_driver(settings: &PgSettings) -> Result<(Client, JoinHandle<()>), PgError> {
    let password = read_password(Path::new(&settings.password_file))?;
    let tls: MakeRustlsConnect = MakeRustlsConnect::new(client_config(Path::new(&settings.ca_file))?);
    let config = pg_config(settings, &password);
    let attempt = config.connect(tls);
    let (client, connection) = timeout(Duration::from_secs(settings.connect_timeout_secs), attempt)
        .await
        .map_err(|_elapsed| PgError::ConnectTimeout {
            seconds: settings.connect_timeout_secs,
        })?
        .map_err(reduce)?;
    Ok((client, tokio::spawn(drive(connection))))
}


/// The connection task runs detached and ends when the client is dropped or the server closes the connection.
pub async fn connect(settings: &PgSettings) -> Result<Client, PgError> {
    connect_with_driver(settings).await.map(|(client, _driver)| client)
}


/// Connects with the settings in force now; a later reload does not touch the returned client.
pub async fn connect_current(engine: &ReloadEngine<PgSettings>) -> Result<Client, PgError> {
    let settings = current_config(engine);
    connect(&settings).await
}
