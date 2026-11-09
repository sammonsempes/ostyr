use crate::error::TransportError;
use crate::limits::{MAX_MAIL_BODY_BYTES, MAX_MAIL_SUBJECT_BYTES, SMTP_DEADLINE_FACTOR};
use crate::load::read_file_limited;
use crate::model::{Channel, Message};
use crate::secret::read_secret;
use crate::settings::{SmtpSettings, SmtpTls, TransportSettings};
use crate::transport::{check_text, FORBIDDEN_CHARS};
use crate::types::MailOutcome;
use lettre::address::Address;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::{Message as Mail, SmtpTransport, Transport};
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::thread::spawn;
use std::time::Duration;


pub const LINE_BREAKS: [char; 2] = ['\r', '\n'];


/// Parsed by `lettre::Address`; a line break or one of the separators U+2028, U+2029, U+0085, NUL is refused before parsing.
pub fn parse_address(text: &str) -> Result<Address, TransportError> {
    if text.contains(FORBIDDEN_CHARS) || text.contains(LINE_BREAKS) {
        Err(TransportError::ForbiddenChar)
    } else {
        text.parse::<Address>().map_err(TransportError::Address)
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
pub fn tls_parameters(settings: &TransportSettings, host: &str) -> Result<TlsParameters, TransportError> {
    let base = TlsParameters::builder(host.to_owned());
    let configured = match &settings.ca_file {
        Some(path) => {
            let pem = read_file_limited(Path::new(path)).map_err(|error| TransportError::CaFile(Box::new(error)))?;
            base.certificate_store(CertificateStore::None)
                .add_root_certificate(Certificate::from_pem(pem.as_bytes()).map_err(TransportError::SmtpCertificate)?)
        }
        None => base.certificate_store(CertificateStore::WebpkiRoots),
    };
    configured.build_rustls().map_err(TransportError::Tls)
}


/// The password comes from the channel's `secret_file` through the checked-handle reader; without a secret file no authentication is attempted.
pub fn credentials_for(settings: &TransportSettings, channel: &Channel, smtp: &SmtpSettings) -> Result<Option<Credentials>, TransportError> {
    match (&channel.secret_file, &smtp.username) {
        (None, _) => Ok(None),
        (Some(_), None) => Err(TransportError::NoUsername),
        (Some(file), Some(username)) => {
            let secret = read_secret(settings, &channel.tenant, file)?;
            Ok(Some(Credentials::new(username.clone(), secret.as_str().to_owned())))
        }
    }
}


/// TLS is mandatory: `Tls::Required` fails when STARTTLS is not offered, `Tls::Wrapper` is TLS from the first byte; the timeout covers each network step.
pub fn build_transport(settings: &TransportSettings, smtp: &SmtpSettings, credentials: Option<Credentials>) -> Result<SmtpTransport, TransportError> {
    let parameters = tls_parameters(settings, &smtp.host)?;
    let tls = match smtp.tls {
        SmtpTls::Starttls => Tls::Required(parameters),
        SmtpTls::Implicit => Tls::Wrapper(parameters),
    };
    let base = SmtpTransport::builder_dangerous(smtp.host.as_str())
        .port(smtp.port)
        .tls(tls)
        .authentication(vec![Mechanism::Plain])
        .timeout(Some(Duration::from_millis(settings.timeout_millis)));
    Ok(match credentials {
        Some(known) => base.credentials(known),
        None => base,
    }
    .build())
}


/// Delivers from the worker thread; the receiver may be gone when the deadline already passed.
pub fn hand_over(sender: &Sender<MailOutcome>, outcome: MailOutcome) {
    if sender.send(outcome).is_err() {
        tracing::debug!("mail outcome dropped after the deadline");
    }
}


/// The total deadline: lettre bounds each network step, this bounds the whole exchange (a server dripping one byte at a time).
pub fn deliver_within(transport: SmtpTransport, mail: Mail, deadline: Duration) -> Result<(), TransportError> {
    let (sender, receiver) = channel();
    spawn(move || hand_over(&sender, transport.send(&mail).map(|_response| ())));
    receiver
        .recv_timeout(deadline)
        .map_err(TransportError::Deadline)?
        .map_err(TransportError::Smtp)
}


/// One mail with one settings snapshot; the server's reply text never reaches an error.
pub fn send_mail(settings: &TransportSettings, channel: &Channel, message: &Message) -> Result<(), TransportError> {
    check_mail(message)?;
    let smtp = settings.smtp.as_ref().ok_or(TransportError::SmtpNotConfigured)?;
    let recipient = parse_address(&channel.target)?;
    let sender = parse_address(&smtp.from)?;
    let mail = Mail::builder()
        .from(Mailbox::new(None, sender))
        .to(Mailbox::new(None, recipient))
        .subject(message.subject.as_str())
        .header(ContentType::TEXT_PLAIN)
        .body(message.body.clone())
        .map_err(TransportError::Build)?;
    let transport = build_transport(settings, smtp, credentials_for(settings, channel, smtp)?)?;
    deliver_within(transport, mail, Duration::from_millis(settings.timeout_millis) * SMTP_DEADLINE_FACTOR)
}
