use crate::auth::{authserv_id, merge, verdicts};
use crate::error::TriageError;
use crate::limits::Limits;
use crate::model::{AttachmentInfo, AuthVerdicts, Counts, Triage};
use crate::scan::scan;
use crate::text::{clean, clean_address};
use crate::urls::{collect, html_text, URL_RULE};
use data_encoding::HEXLOWER;
use mail_parser::{Address, Header, HeaderValue, Message, MessageParser, MessagePart, MimeHeaders, PartType};
use regex::Regex;
use sha2::{Digest, Sha256};


const EML_SUFFIX: &str = ".eml";


const DEFAULT_TYPE: &str = "application/octet-stream";


const AUTH_HEADER: &str = "authentication-results";


const FROM_HEADER: &str = "from";


const RETURN_PATH_HEADER: &str = "return-path";


const SUBJECT_HEADER: &str = "subject";


pub fn triage(raw: &[u8]) -> Result<Triage, TriageError> {
    triage_with(raw, &Limits::default())
}


pub fn triage_with(raw: &[u8], limits: &Limits) -> Result<Triage, TriageError> {
    triage_with_rule(raw, limits, &URL_RULE)
}


/// One reported message in, one record out; the rule is injected so a failing pattern is testable.
pub fn triage_with_rule(raw: &[u8], limits: &Limits, rule: &Result<Regex, regex::Error>) -> Result<Triage, TriageError> {
    if raw.len() > limits.message_bytes {
        Err(TriageError::TooLarge)
    } else {
        parse_and_extract(raw, limits, rule)
    }
}


fn parse_and_extract(raw: &[u8], limits: &Limits, rule: &Result<Regex, regex::Error>) -> Result<Triage, TriageError> {
    let scanned = scan(raw, limits);
    let root = parse_owned(scanned.usable).ok_or(TriageError::Unparsable)?;
    let mut counts = Counts {
        scan_cut: usize::from(scanned.cut),
        ..Counts::default()
    };
    let (found, capped) = descend(&root, limits);
    counts.nesting_cut = usize::from(capped);
    let target = found.as_ref().unwrap_or(&root);
    counts.headers_skipped += target.headers().len().saturating_sub(limits.headers);
    counts.parts_skipped += target.parts.len().saturating_sub(limits.parts);
    let headers = header_slice(target, limits);
    let sender = find_header(headers, FROM_HEADER, limits, &mut counts)
        .and_then(|header| address_of(header.value()))
        .and_then(|address| clean_address(address, limits.address_bytes, &mut counts));
    let return_path = find_header(headers, RETURN_PATH_HEADER, limits, &mut counts)
        .and_then(|header| address_of(header.value()))
        .and_then(|address| clean_address(address, limits.address_bytes, &mut counts));
    let subject = find_header(headers, SUBJECT_HEADER, limits, &mut counts)
        .and_then(|header| header.value().as_text())
        .map(|text| clean(text, limits.subject_chars, &mut counts));
    let auth = authentication(&root, limits, &mut counts);
    let urls = collect_urls(target, limits, rule, &mut counts);
    let attachments = list_attachments(target, limits, &mut counts);
    Ok(Triage {
        sender,
        return_path,
        auth,
        subject,
        urls,
        attachments,
        counts,
    })
}


/// A message needs one header with a value: the parser reads any bytes as a header name with no value.
fn parse_owned(bytes: &[u8]) -> Option<Message<'static>> {
    MessageParser::default()
        .parse(bytes)
        .filter(|message| message.headers().iter().any(|header| !header.value().is_empty()))
        .map(Message::into_owned)
}


fn is_eml(part: &MessagePart<'static>) -> bool {
    part.attachment_name().is_some_and(|name| name.to_ascii_lowercase().ends_with(EML_SUFFIX))
}


fn nested(part: &MessagePart<'static>, limits: &Limits) -> Option<Message<'static>> {
    match &part.body {
        PartType::Message(inner) => Some(inner.clone()),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => eml_message(part, bytes, limits),
        _ => None,
    }
}


fn eml_message(part: &MessagePart<'static>, bytes: &[u8], limits: &Limits) -> Option<Message<'static>> {
    if is_eml(part) && bytes.len() <= limits.part_bytes {
        parse_owned(bytes)
    } else {
        None
    }
}


fn inner(message: &Message<'static>, limits: &Limits) -> Option<Message<'static>> {
    message.parts.iter().take(limits.parts).find_map(|part| nested(part, limits))
}


/// Walks into the attached message at most `limits.nesting` times; the flag says an attached message was left unopened.
fn descend(root: &Message<'static>, limits: &Limits) -> (Option<Message<'static>>, bool) {
    let walked = (0..limits.nesting).try_fold(None::<Message<'static>>, |current, _| {
        match inner(current.as_ref().unwrap_or(root), limits) {
            Some(found) => Ok(Some(found)),
            None => Err(current),
        }
    });
    match walked {
        Ok(last) => {
            let more = inner(last.as_ref().unwrap_or(root), limits).is_some();
            (last, more)
        }
        Err(last) => (last, false),
    }
}


fn header_slice<'a>(message: &'a Message<'static>, limits: &Limits) -> &'a [Header<'static>] {
    let all = message.headers();
    all.get(..limits.headers).unwrap_or(all)
}


fn within_bound<'a>(header: &'a Header<'static>, limits: &Limits, counts: &mut Counts) -> Option<&'a Header<'static>> {
    let oversized = header.offset_end.saturating_sub(header.offset_start) as usize > limits.header_bytes;
    counts.headers_skipped += usize::from(oversized);
    (!oversized).then_some(header)
}


fn find_header<'a>(headers: &'a [Header<'static>], name: &str, limits: &Limits, counts: &mut Counts) -> Option<&'a Header<'static>> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| within_bound(header, limits, counts))
}


fn address_of<'a>(value: &'a HeaderValue<'static>) -> Option<&'a str> {
    match value {
        HeaderValue::Address(Address::List(list)) => list.first().and_then(|addr| addr.address.as_deref()),
        HeaderValue::Address(Address::Group(groups)) => groups
            .first()
            .and_then(|group| group.addresses.first())
            .and_then(|addr| addr.address.as_deref()),
        HeaderValue::Text(text) => Some(text.as_ref()),
        _ => None,
    }
}


fn is_auth_header(header: &Header<'static>) -> bool {
    header.name().eq_ignore_ascii_case(AUTH_HEADER)
}


/// The receiving server's run of `Authentication-Results` headers from the topmost one, with the topmost one's authserv-id.
fn authentication(root: &Message<'static>, limits: &Limits, counts: &mut Counts) -> AuthVerdicts {
    let texts: Vec<Option<&str>> = header_slice(root, limits)
        .iter()
        .skip_while(|header| !is_auth_header(header))
        .take_while(|header| is_auth_header(header))
        .map(|header| within_bound(header, limits, counts).and_then(|bounded| bounded.value().as_text()))
        .collect();
    let trusted = texts.first().copied().flatten().map(authserv_id);
    texts.iter().flatten().fold(AuthVerdicts::default(), |found, text| {
        if Some(authserv_id(text)) == trusted {
            merge(found, verdicts(text, counts))
        } else {
            counts.auth_refused += 1;
            found
        }
    })
}


fn collect_urls(target: &Message<'static>, limits: &Limits, rule: &Result<Regex, regex::Error>, counts: &mut Counts) -> Vec<String> {
    target.parts.iter().take(limits.parts).fold(Vec::new(), |known, part| {
        let oversized = part.len() > limits.part_bytes;
        match &part.body {
            PartType::Text(_) | PartType::Html(_) if oversized => {
                counts.parts_skipped += 1;
                known
            }
            PartType::Text(text) => collect(rule, text, limits, known, counts),
            PartType::Html(html) => collect(rule, &html_text(html), limits, known, counts),
            _ => known,
        }
    })
}


fn declared_type(part: &MessagePart<'_>, limits: &Limits, counts: &mut Counts) -> String {
    let declared = part.content_type().map_or_else(
        || DEFAULT_TYPE.to_owned(),
        |content_type| {
            content_type.subtype().map_or_else(
                || content_type.ctype().to_owned(),
                |subtype| format!("{}/{subtype}", content_type.ctype()),
            )
        },
    );
    clean(&declared, limits.name_chars, counts)
}


fn describe(part: &MessagePart<'_>, limits: &Limits, counts: &mut Counts) -> Option<AttachmentInfo> {
    let oversized = part.len() > limits.part_bytes;
    counts.attachments_skipped += usize::from(oversized);
    (!oversized).then(|| AttachmentInfo {
        file_name: part.attachment_name().map(|name| clean(name, limits.name_chars, counts)),
        content_type: declared_type(part, limits, counts),
        size: part.len(),
        sha256: HEXLOWER.encode(&Sha256::digest(part.contents())),
    })
}


fn list_attachments(target: &Message<'static>, limits: &Limits, counts: &mut Counts) -> Vec<AttachmentInfo> {
    counts.attachments_skipped += target.attachment_count().saturating_sub(limits.attachments);
    target
        .attachments()
        .take(limits.attachments)
        .filter_map(|part| describe(part, limits, counts))
        .collect()
}
