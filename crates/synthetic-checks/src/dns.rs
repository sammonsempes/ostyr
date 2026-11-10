use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::{Resolver, TokioResolver};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::time::timeout;


fn nameserver_config(nameserver: SocketAddr) -> ResolverConfig {
    let mut udp = ConnectionConfig::udp();
    udp.port = nameserver.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = nameserver.port();
    ResolverConfig::from_parts(None, Vec::new(), vec![NameServerConfig::new(nameserver.ip(), true, vec![udp, tcp])])
}


fn build_resolver(nameserver: Option<SocketAddr>, left: Duration) -> Result<TokioResolver, NetError> {
    let mut builder = match nameserver {
        Some(socket) => Resolver::builder_with_config(nameserver_config(socket), TokioRuntimeProvider::default()),
        None => TokioResolver::builder_tokio()?,
    };
    let options = builder.options_mut();
    options.cache_size = 0;
    options.attempts = 1;
    options.timeout = left;
    options.use_hosts_file = ResolveHosts::Never;
    builder.build()
}


async fn lookup(nameserver: Option<SocketAddr>, name: &str, left: Duration, cap: usize) -> io::Result<Vec<IpAddr>> {
    let resolver = build_resolver(nameserver, left).map_err(io::Error::other)?;
    let answers = resolver.lookup_ip(name).await.map_err(io::Error::other)?;
    Ok(answers.iter().take(cap).collect())
}


/// The real `Resolve`: A and AAAA through a fresh resolver (no cache, no hosts file) against `nameserver` or the system configuration.
pub fn dns_resolve(nameserver: Option<SocketAddr>, name: &str, left: Duration, cap: usize) -> io::Result<Vec<IpAddr>> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async { timeout(left, lookup(nameserver, name, left, cap)).await.map_err(io::Error::from)? })
}
