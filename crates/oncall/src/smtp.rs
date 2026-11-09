use crate::error::TransportError;
use crate::limits::{MAX_CONNECT_ADDRESSES, MAX_MAIL_BODY_BYTES, MAX_MAIL_SUBJECT_BYTES};
use crate::load::read_file_limited;
use crate::model::{Channel, Message};
use crate::secret::read_secret;
use crate::settings::{SmtpSettings, SmtpTls, TransportSettings};
use crate::transport::{check_text, FORBIDDEN_CHARS};
use crate::types::ClockFn;
use crate::wire::{connect_first, handshake, io_error, read_reply, read_some, send, Link, Reply};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lettre::address::Address;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::Message as Mail;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::pem::PemObject;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;


pub const LINE_BREAKS: [char; 2] = ['\r', '\n'];


pub const LOCAL_PART_SPECIALS: &str = "!#$%&'*+-/=?^_`{|}~.";


pub const CLIENT_NAME: &str = "localhost";


pub const CODE_SERVICE_READY: u16 = 220;


pub const CODE_QUIT: u16 = 221;


pub const CODE_OK: u16 = 250;


pub const CODE_AUTHENTICATED: u16 = 235;


pub const CODE_START_DATA: u16 = 354;


/// The TLS side of one send: how it starts, the client configuration and the name the certificate must match.
pub struct TlsPlan {
    pub mode: SmtpTls,
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
}


/// The AUTH PLAIN credentials; the password is zeroised on drop.
pub struct Login {
    pub username: String,
    pub password: Zeroizing<String>,
}


/// Envelope addresses and the dot-stuffed message, ready for the DATA step.
pub struct Envelope {
    pub sender: String,
    pub recipient: String,
    pub data: String,
}


/// Parsed by `lettre::Address`, then a quoted or non-ASCII address, a domain literal or a domain label outside letters, digits and hyphens is refused.
pub fn parse_address(text: &str) -> Result<Address, TransportError> {
    if text.contains(FORBIDDEN_CHARS) || text.contains(LINE_BREAKS) {
        Err(TransportError::ForbiddenChar)
    } else {
        let address = text.parse::<Address>().map_err(TransportError::Address)?;
        let plain = address
            .user()
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || LOCAL_PART_SPECIALS.contains(character));
        let labels = address
            .domain()
            .split('.')
            .all(|label| label.chars().all(|symbol| symbol.is_ascii_alphanumeric() || symbol == '-'));
        if plain && labels && !address.user().starts_with('-') {
            Ok(address)
        } else {
            Err(TransportError::AddressForm)
        }
    }
}


/// No line break in the subject (the header), and bounded bytes for subject and body.
pub fn check_mail(message: &Message) -> Result<(), TransportError> {
    check_text(message)?;
    if message.subject.contains(LINE_BREAKS) || message.subject.len() > MAX_MAIL_SUBJECT_BYTES || message.body.len() > MAX_MAIL_BODY_BYTES {
        Err(TransportError::MailText)
    } else {
        Ok(())
    }
}


/// With a CA file only that CA is trusted, else the Mozilla roots; certificate and host name are always checked.
pub fn root_store(settings: &TransportSettings) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    match &settings.ca_file {
        Some(path) => {
            let pem = read_file_limited(Path::new(path)).map_err(|error| TransportError::CaFile(Box::new(error)))?;
            let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(TransportError::SmtpCertificate)?;
            if certificates.is_empty() {
                Err(TransportError::NoCertificate)
            } else {
                certificates
                    .into_iter()
                    .try_for_each(|certificate| roots.add(certificate).map_err(TransportError::Tls))
            }
        }
        None => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Ok(())
        }
    }?;
    Ok(roots)
}


pub fn tls_plan(settings: &TransportSettings, smtp: &SmtpSettings) -> Result<TlsPlan, TransportError> {
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(TransportError::Tls)?
        .with_root_certificates(root_store(settings)?)
        .with_no_client_auth();
    let name = ServerName::try_from(smtp.host.clone()).map_err(TransportError::InvalidHost)?;
    Ok(TlsPlan {
        mode: smtp.tls,
        config: Arc::new(config),
        name,
    })
}


/// The password comes from the channel's `secret_file` through the checked-handle reader; without a secret file no authentication is attempted.
pub fn login_for(settings: &TransportSettings, channel: &Channel, smtp: &SmtpSettings) -> Result<Option<Login>, TransportError> {
    match (&channel.secret_file, &smtp.username) {
        (None, _) => Ok(None),
        (Some(_), None) => Err(TransportError::NoUsername),
        (Some(file), Some(username)) => Ok(Some(Login {
            username: username.clone(),
            password: read_secret(settings, &channel.tenant, file)?,
        })),
    }
}


/// Every line ending becomes CRLF (a bare LF or CR could end DATA on a lenient server), a leading dot is doubled, then the terminator.
pub fn data_block(formatted: &[u8]) -> String {
    let text = String::from_utf8_lossy(formatted)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let stuffed: String = text
        .split_inclusive("\r\n")
        .map(|line| if line.starts_with('.') { format!(".{line}") } else { line.to_owned() })
        .collect();
    if stuffed.ends_with("\r\n") {
        format!("{stuffed}.\r\n")
    } else {
        format!("{stuffed}\r\n.\r\n")
    }
}


/// One command and its reply, which must carry `expected`; the command copy is zeroised (AUTH holds the password).
pub fn exchange(link: &mut Link, command: &str, expected: u16) -> Result<Reply, TransportError> {
    let wire = Zeroizing::new(format!("{command}\r\n"));
    send(link, wire.as_bytes())?;
    expect(read_reply(&mut |buffer| read_some(link, buffer))?, expected)
}


pub fn expect(reply: Reply, code: u16) -> Result<Reply, TransportError> {
    if reply.code == code {
        Ok(reply)
    } else {
        Err(TransportError::Rejected { code: reply.code })
    }
}


pub fn offers_starttls(capabilities: &Reply) -> bool {
    capabilities.lines.iter().any(|line| line.eq_ignore_ascii_case("STARTTLS"))
}


pub fn offers_plain(capabilities: &Reply) -> bool {
    capabilities.lines.iter().any(|line| {
        let upper = line.to_ascii_uppercase();
        let mut words = upper.split([' ', '=']);
        words.next() == Some("AUTH") && words.any(|word| word == "PLAIN")
    })
}


/// Starts TLS on the open socket: the handshake runs under the total deadline and the certificate is checked against the plan.
pub fn upgrade(link: &mut Link, plan: &TlsPlan) -> Result<(), TransportError> {
    let mut connection = ClientConnection::new(plan.config.clone(), plan.name.clone()).map_err(TransportError::Tls)?;
    handshake(&mut connection, &mut link.tcp, link.deadline, link.clock)?;
    link.tls = Some(connection);
    Ok(())
}


/// AUTH PLAIN, only when the server offers it on the secured connection.
pub fn authenticate(link: &mut Link, capabilities: &Reply, login: &Login) -> Result<(), TransportError> {
    if offers_plain(capabilities) {
        let raw = Zeroizing::new([&[0][..], login.username.as_bytes(), &[0], login.password.as_bytes()].concat());
        let encoded = Zeroizing::new(STANDARD.encode(&*raw));
        let command = Zeroizing::new(format!("AUTH PLAIN {}", encoded.as_str()));
        exchange(link, command.as_str(), CODE_AUTHENTICATED).map(|_reply| ())
    } else {
        Err(TransportError::NoAuth)
    }
}


/// The whole dialogue: greeting, EHLO, STARTTLS (or TLS from the first byte), EHLO again, AUTH, one mail, QUIT.
pub fn converse(link: &mut Link, plan: &TlsPlan, login: Option<&Login>, envelope: &Envelope) -> Result<(), TransportError> {
    if matches!(plan.mode, SmtpTls::Implicit) {
        upgrade(link, plan)?;
    }
    expect(read_reply(&mut |buffer| read_some(link, buffer))?, CODE_SERVICE_READY)?;
    let plain = exchange(link, &format!("EHLO {CLIENT_NAME}"), CODE_OK)?;
    let capabilities = match plan.mode {
        SmtpTls::Starttls => {
            if !offers_starttls(&plain) {
                Err(TransportError::NoStarttls)?;
            }
            exchange(link, "STARTTLS", CODE_SERVICE_READY)?;
            upgrade(link, plan)?;
            exchange(link, &format!("EHLO {CLIENT_NAME}"), CODE_OK)?
        }
        SmtpTls::Implicit => plain,
    };
    login.map(|known| authenticate(link, &capabilities, known)).transpose()?;
    exchange(link, &format!("MAIL FROM:<{}>", envelope.sender), CODE_OK)?;
    exchange(link, &format!("RCPT TO:<{}>", envelope.recipient), CODE_OK)?;
    exchange(link, "DATA", CODE_START_DATA)?;
    send(link, envelope.data.as_bytes())?;
    expect(read_reply(&mut |buffer| read_some(link, buffer))?, CODE_OK)?;
    if exchange(link, "QUIT", CODE_QUIT).is_err() {
        tracing::debug!("the server did not confirm QUIT after accepting the mail");
    }
    Ok(())
}


pub fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, TransportError> {
    Ok((host, port).to_socket_addrs().map_err(io_error)?.take(MAX_CONNECT_ADDRESSES).collect())
}


/// One mail with one settings snapshot and the real clock.
pub fn send_mail(settings: &TransportSettings, channel: &Channel, message: &Message) -> Result<(), TransportError> {
    send_mail_with(settings, channel, message, &Instant::now)
}


/// `timeout_millis` is the total deadline of the send (connect, handshake and every reply), read through `clock`; the reply text never reaches an error.
pub fn send_mail_with(settings: &TransportSettings, channel: &Channel, message: &Message, clock: ClockFn) -> Result<(), TransportError> {
    check_mail(message)?;
    let smtp = settings.smtp.as_ref().ok_or(TransportError::SmtpNotConfigured)?;
    let recipient = parse_address(&channel.target)?;
    let sender = parse_address(&smtp.from)?;
    let mail = Mail::builder()
        .from(Mailbox::new(None, sender.clone()))
        .to(Mailbox::new(None, recipient.clone()))
        .subject(message.subject.as_str())
        .header(ContentType::TEXT_PLAIN)
        .body(message.body.clone())
        .map_err(TransportError::Build)?;
    let plan = tls_plan(settings, smtp)?;
    let login = login_for(settings, channel, smtp)?;
    let envelope = Envelope {
        sender: sender.to_string(),
        recipient: recipient.to_string(),
        data: data_block(&mail.formatted()),
    };
    let deadline = clock() + Duration::from_millis(settings.timeout_millis);
    let tcp = connect_first(&resolve(&smtp.host, smtp.port)?, deadline, clock)?;
    converse(
        &mut Link {
            tcp,
            tls: None,
            deadline,
            clock,
        },
        &plan,
        login.as_ref(),
        &envelope,
    )
}
