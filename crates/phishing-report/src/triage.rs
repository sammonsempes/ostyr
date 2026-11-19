use crate::auth::verdicts;
use crate::error::TriageError;
use crate::limits::Limits;
use crate::model::{AttachmentInfo, AuthVerdicts, Counts, LevelInfo, Triage, UrlHit};
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


#[derive(Debug, Clone, Copy)]
struct Context<'a> {
    trusted: &'a [String],
    limits: &'a Limits,
    rule: &'a Result<Regex, regex::Error>,
    first: usize,
}


pub fn triage(raw: &[u8], trusted: &[String]) -> Result<Triage, TriageError> {
    triage_with(raw, trusted, &Limits::default())
}


pub fn triage_with(raw: &[u8], trusted: &[String], limits: &Limits) -> Result<Triage, TriageError> {
    triage_with_rule(raw, trusted, limits, &URL_RULE)
}


/// One reported message in, one record out; the rule is injected so a failing pattern is testable.
pub fn triage_with_rule(raw: &[u8], trusted: &[String], limits: &Limits, rule: &Result<Regex, regex::Error>) -> Result<Triage, TriageError> {
    if raw.len() > limits.message_bytes {
        Err(TriageError::TooLarge)
    } else {
        parse_and_extract(raw, trusted, limits, rule)
    }
}


fn parse_and_extract(raw: &[u8], trusted: &[String], limits: &Limits, rule: &Result<Regex, regex::Error>) -> Result<Triage, TriageError> {
    let scanned = scan(raw, limits);
    let root = parse_message(scanned.usable).ok_or(TriageError::Unparsable)?;
    let mut counts = Counts {
        scan_cut: usize::from(scanned.cut),
        ..Counts::default()
    };
    let chain = open_chain(root, limits, &mut counts);
    let context = Context {
        trusted,
        limits,
        rule,
        first: usize::from(chain.len() > 1),
    };
    let start = Triage { counts, ..Triage::default() };
    Ok(chain
        .iter()
        .enumerate()
        .fold(start, |record, (index, message)| read_level(record, index, message, &context)))
}


/// A message needs one header with a value: the parser reads any bytes as a header name with no value.
fn parse_message(bytes: &[u8]) -> Option<Message<'_>> {
    MessageParser::default()
        .parse(bytes)
        .filter(|message| message.headers().iter().any(|header| !header.value().is_empty()))
}


fn is_eml(part: &MessagePart<'_>) -> bool {
    part.attachment_name().is_some_and(|name| name.to_ascii_lowercase().ends_with(EML_SUFFIX))
}


fn is_attached_message(part: &MessagePart<'_>) -> bool {
    match &part.body {
        PartType::Message(_) => true,
        PartType::Binary(_) | PartType::InlineBinary(_) => is_eml(part),
        _ => false,
    }
}


fn attached_count(message: &Message<'_>, limits: &Limits) -> usize {
    message.parts.iter().take(limits.parts).filter(|part| is_attached_message(part)).count()
}


fn eml_message(part: &MessagePart<'_>, bytes: &[u8], limits: &Limits, counts: &mut Counts) -> Option<Message<'static>> {
    let eligible = is_eml(part) && bytes.len() <= limits.part_bytes;
    eligible.then(|| scan(bytes, limits)).and_then(|scanned| {
        counts.scan_cut += usize::from(scanned.cut);
        parse_message(scanned.usable).map(Message::into_owned)
    })
}


fn open<'a>(part: &MessagePart<'a>, limits: &Limits, counts: &mut Counts) -> Option<Message<'a>> {
    match &part.body {
        PartType::Message(inner) => Some(inner.clone()),
        PartType::Binary(bytes) | PartType::InlineBinary(bytes) => eml_message(part, bytes, limits, counts),
        _ => None,
    }
}


fn first_attached<'a>(message: &Message<'a>, limits: &Limits, counts: &mut Counts) -> Option<Message<'a>> {
    message.parts.iter().take(limits.parts).find_map(|part| open(part, limits, counts))
}


/// The forward, then the first attached message of each level, at most `limits.nesting` levels; what stays unopened is counted.
fn open_chain<'a>(root: Message<'a>, limits: &Limits, counts: &mut Counts) -> Vec<Message<'a>> {
    let chain = (0..limits.nesting)
        .try_fold(vec![root], |mut levels, _| {
            match levels.last().and_then(|last| first_attached(last, limits, counts)) {
                Some(next) => {
                    levels.push(next);
                    Ok(levels)
                }
                None => Err(levels),
            }
        })
        .unwrap_or_else(std::convert::identity);
    let attached: usize = chain.iter().map(|message| attached_count(message, limits)).sum();
    counts.messages_unopened += attached.saturating_sub(chain.len().saturating_sub(1));
    let at_limit = chain.len() > limits.nesting;
    counts.nesting_cut += usize::from(at_limit && chain.last().is_some_and(|last| attached_count(last, limits) > 0));
    chain
}


fn header_slice<'a, 'b>(message: &'a Message<'b>, limits: &Limits) -> &'a [Header<'b>] {
    let all = message.headers();
    all.get(..limits.headers).unwrap_or(all)
}


fn header_bytes(header: &Header<'_>) -> usize {
    header.offset_end.saturating_sub(header.offset_start) as usize
}


fn find_header<'a, 'b>(headers: &'a [Header<'b>], name: &str, limits: &Limits, counts: &mut Counts) -> Option<&'a Header<'b>> {
    headers.iter().find(|header| header.name().eq_ignore_ascii_case(name)).filter(|header| {
        let oversized = header_bytes(header) > limits.header_bytes;
        counts.headers_skipped += usize::from(oversized);
        !oversized
    })
}


fn address_of<'a>(value: &'a HeaderValue<'_>) -> Option<&'a str> {
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


fn address_header(headers: &[Header<'_>], name: &str, limits: &Limits, counts: &mut Counts) -> Option<String> {
    find_header(headers, name, limits, counts)
        .and_then(|header| address_of(header.value()))
        .and_then(|address| clean_address(address, limits.address_bytes, counts))
}


fn is_auth_header(header: &Header<'_>) -> bool {
    header.name().eq_ignore_ascii_case(AUTH_HEADER)
}


/// The raw header value, never the decoded one: an RFC 2047 word in a property could decode into a semicolon and a fake result.
fn raw_value<'a>(message: &'a Message<'_>, header: &Header<'_>) -> Option<&'a str> {
    let base = message.headers().first().map_or(0, |first| first.offset_field) as usize;
    let raw = message.raw_message();
    let relative = |offset: u32| (offset as usize).checked_sub(base);
    let name = header.name().as_bytes();
    let name_found = relative(header.offset_field)
        .and_then(|start| raw.get(start..start.saturating_add(name.len())))
        .is_some_and(|found| found.eq_ignore_ascii_case(name));
    let value = relative(header.offset_start)
        .zip(relative(header.offset_end))
        .and_then(|(start, end)| raw.get(start..end));
    match (name_found, value.map(std::str::from_utf8)) {
        (true, Some(Ok(text))) => Some(text),
        _ => None,
    }
}


fn authentication(message: &Message<'_>, context: &Context<'_>, counts: &mut Counts) -> AuthVerdicts {
    let limits = context.limits;
    let found: Vec<&Header<'_>> = header_slice(message, limits).iter().filter(|header| is_auth_header(header)).collect();
    let oversized = found.iter().filter(|header| header_bytes(header) > limits.header_bytes).count();
    counts.headers_skipped += oversized;
    let texts: Vec<Option<&str>> = found
        .iter()
        .filter(|header| header_bytes(header) <= limits.header_bytes)
        .map(|header| raw_value(message, header))
        .collect();
    verdicts(&texts, context.trusted, oversized > 0, counts)
}


fn level_info(message: &Message<'_>, level: usize, context: &Context<'_>, counts: &mut Counts) -> LevelInfo {
    let limits = context.limits;
    counts.headers_skipped += message.headers().len().saturating_sub(limits.headers);
    counts.parts_skipped += message.parts.len().saturating_sub(limits.parts);
    let headers = header_slice(message, limits);
    let sender = address_header(headers, FROM_HEADER, limits, counts);
    let return_path = address_header(headers, RETURN_PATH_HEADER, limits, counts);
    let subject = find_header(headers, SUBJECT_HEADER, limits, counts)
        .and_then(|header| header.value().as_text())
        .map(|text| clean(text, limits.subject_chars, counts));
    LevelInfo {
        level,
        sender,
        return_path,
        subject,
        auth: authentication(message, context, counts),
    }
}


fn read_level(mut record: Triage, index: usize, message: &Message<'_>, context: &Context<'_>) -> Triage {
    let info = level_info(message, index, context, &mut record.counts);
    if index < context.first {
        record.reporter_auth = Some(info.auth);
    } else {
        if index == context.first {
            record.sender = info.sender.clone();
            record.return_path = info.return_path.clone();
            record.subject = info.subject.clone();
            record.auth = info.auth.clone();
        }
        let known = std::mem::take(&mut record.urls);
        record.urls = collect_urls(message, index, context, known, &mut record.counts);
        let room = context.limits.attachments.saturating_sub(record.attachments.len());
        let listed = list_attachments(message, index, context.limits, room, &mut record.counts);
        record.attachments.extend(listed);
        record.levels.push(info);
    }
    record
}


fn collect_urls(message: &Message<'_>, level: usize, context: &Context<'_>, known: Vec<UrlHit>, counts: &mut Counts) -> Vec<UrlHit> {
    let limits = context.limits;
    message.parts.iter().take(limits.parts).fold(known, |urls, part| {
        let oversized = part.len() > limits.part_bytes;
        match &part.body {
            PartType::Text(_) | PartType::Html(_) if oversized => {
                counts.parts_skipped += 1;
                urls
            }
            PartType::Text(text) => collect(context.rule, text, level, limits, urls, counts),
            PartType::Html(html) => {
                let decoded = html_text(html, counts);
                collect(context.rule, &decoded, level, limits, urls, counts)
            }
            _ => urls,
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


fn describe(part: &MessagePart<'_>, level: usize, limits: &Limits, counts: &mut Counts) -> Option<AttachmentInfo> {
    let oversized = part.len() > limits.part_bytes;
    counts.attachments_skipped += usize::from(oversized);
    (!oversized).then(|| AttachmentInfo {
        level,
        file_name: part.attachment_name().map(|name| clean(name, limits.name_chars, counts)),
        content_type: declared_type(part, limits, counts),
        size: part.len(),
        sha256: HEXLOWER.encode(&Sha256::digest(part.contents())),
    })
}


fn list_attachments(message: &Message<'_>, level: usize, limits: &Limits, room: usize, counts: &mut Counts) -> Vec<AttachmentInfo> {
    counts.attachments_skipped += message.attachment_count().saturating_sub(room);
    message
        .attachments()
        .take(room)
        .filter_map(|part| describe(part, level, limits, counts))
        .collect()
}
