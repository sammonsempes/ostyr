use crate::error::HostError;
use crate::limits::{MAX_HOST_HEADER_BYTES, MAX_PORT_DIGITS, UNKNOWN_DOMAIN_EN, UNKNOWN_DOMAIN_FR};
use crate::model::RenderedPage;
use crate::name::normalise_name;
use crate::policy::SinkholePage;
use html_escape::encode_quoted_attribute;
use std::str::from_utf8;
use tracing::debug;


pub const PAGE_STATUS: u16 = 200;


/// The port of a `Host` header: 1 to 5 ASCII digits.
pub fn is_port(port: &str) -> bool {
    (1..=MAX_PORT_DIGITS).contains(&port.len()) && port.bytes().all(|byte| byte.is_ascii_digit())
}


/// The name part of `name[:port]`; a second colon (IPv6 literal) makes the port invalid.
pub fn strip_port(text: &str) -> Result<&str, HostError> {
    match text.split_once(':') {
        Some((name, port)) if is_port(port) => Ok(name),
        Some(_) => Err(HostError::BadPort),
        None => Ok(text),
    }
}


/// The WHATWG "ends in a number" test: all decimal digits, or `0x` followed only by hex digits (so `0x7f.0x1` is an address, not a name).
pub fn is_number_label(label: &str) -> bool {
    let hexadecimal = label.strip_prefix("0x").or_else(|| label.strip_prefix("0X"));
    label.bytes().all(|byte| byte.is_ascii_digit()) || hexadecimal.is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}


/// The A-label form of the requested name; every other form is refused with a fixed error that never holds the bytes.
pub fn derive_host(header: Option<&[u8]>) -> Result<String, HostError> {
    let bytes = header.ok_or(HostError::Missing)?;
    if bytes.len() > MAX_HOST_HEADER_BYTES {
        Err(HostError::TooLong)?;
    }
    let name = strip_port(from_utf8(bytes)?)?;
    if name.ends_with('.') {
        Err(HostError::TrailingDot)?;
    }
    let ascii = normalise_name(name)?;
    if ascii.rsplit('.').next().is_some_and(is_number_label) {
        Err(HostError::NumericName)?;
    }
    Ok(ascii)
}


/// A refused header is logged by class only and shown as "unknown domain".
pub fn refused(error: &HostError) -> Option<String> {
    let reason = error.to_string();
    debug!(reason, "sinkhole host refused");
    None
}


pub fn escaped(text: &str) -> String {
    encode_quoted_attribute(text).into_owned()
}


pub fn contact_line(page: Option<&SinkholePage>) -> String {
    page.map_or_else(String::new, |texts| {
        format!(
            "<p>Contact / Contact : {}, {}</p>\n",
            escaped(&texts.organisation),
            escaped(&texts.contact)
        )
    })
}


/// The fixed bilingual page: no script, no external resource, no form, no link. Status 200 whatever the name.
pub fn render_page(page: Option<&SinkholePage>, host_header: Option<&[u8]>) -> RenderedPage {
    let host = derive_host(host_header).map_or_else(|error| refused(&error), Some);
    let english = host.as_deref().map_or_else(|| UNKNOWN_DOMAIN_EN.to_owned(), escaped);
    let french = host.as_deref().map_or_else(|| UNKNOWN_DOMAIN_FR.to_owned(), escaped);
    let contact = contact_line(page);
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Blocked / Bloqu&eacute;</title>\n</head>\n<body>\n\
         <h1>Access blocked</h1>\n<p>The domain <strong>{english}</strong> was blocked by the security policy.</p>\n\
         <h1>Acc&egrave;s bloqu&eacute;</h1>\n<p>Le domaine <strong>{french}</strong> a &eacute;t&eacute; bloqu&eacute; par la politique de s&eacute;curit&eacute;.</p>\n\
         {contact}</body>\n</html>\n"
    );
    RenderedPage { status: PAGE_STATUS, html }
}
