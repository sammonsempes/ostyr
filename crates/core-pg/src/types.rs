use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Connection, Socket};
use tokio_postgres_rustls::MakeRustlsConnect;


pub type TlsStream = <MakeRustlsConnect as MakeTlsConnect<Socket>>::Stream;


pub type TlsConnection = Connection<Socket, TlsStream>;


pub type SqlParameter<'a> = &'a (dyn ToSql + Sync);
