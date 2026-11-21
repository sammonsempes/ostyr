use crate::auth::{verdicts_with_from, PASS};
use crate::claim::{claim_scan, domain_set};
use crate::error::TriageError;
use crate::limits::{Limits, MAX_FROM_ADDRESSES};
use crate::model::{AttachmentInfo, AuthVerdicts, Counts, LevelInfo, ReporterPolicy, Triage, UrlHit};
use crate::policy::{check_policy, is_internal, is_strict_domain};
use crate::scan::{scan, Scan};
use crate::text::{clean, clean_address, is_refused_address};
use crate::types::RawReadFn;
use crate::urls::{collect, html_text, URL_RULE};
use data_encoding::HEXLOWER;
use mail_parser::{Address, Header, HeaderValue, Message, MessageParser, MessagePart, MimeHeaders, PartType};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;


const EML_SUFFIX: &str = ".eml";


const DEFAULT_TYPE: &str = "application/octet-stream";


const AUTH_HEADER: &str = "authentication-results";


const FROM_HEADER: &str = "from";


const RETURN_PATH_HEADER: &str = "return-path";


const SUBJECT_HEADER: &str = "subject";


pub const REPORTER_FORWARD: &str = "forward";


pub const REPORTER_EXTERNAL: &str = "external";


pub const REPORTER_FROM_AMBIGUOUS: &str = "from_ambiguous";


pub const REPORTER_DMARC_MISMATCH: &str = "dmarc_domain_mismatch";


const REPORTER_DMARC_PREFIX: &str = "dmarc_";


pub const ATTACHED_ORIGINAL: &str = "attached_original";


pub const INLINE_FORWARD: &str = "inline_forward";


pub const SOURCE_ATTACHED: &str = "attached";


pub const SOURCE_REPORTED: &str = "reported";


pub const UNCERTAIN_ATTACHED_CLAIM: &str = "attached_claim";


pub const UNCERTAIN_FROM_UNPARSED: &str = "from_unparsed";


pub const UNCERTAIN_DMARC_MISMATCH: &str = "dmarc_domain_mismatch";


pub const UNCERTAIN_INTERNAL_UNAUTHENTICATED: &str = "internal_unauthenticated";


#[derive(Debug, Clone, Copy)]
struct Context<'a> {
    trusted: &'a [String],
    limits: &'a Limits,
    rule: &'a Result<Regex, regex::Error>,
    reporters: &'a ReporterPolicy,
    domains: &'a HashSet<String>,
    has_attached: bool,
}


#[derive(Debug, Clone, Copy)]
struct Adoption {
    internal_claimed: bool,
    from_unparsed: bool,
}


#[derive(Debug)]
struct Facts {
    sender: Option<String>,
    return_path: Option<String>,
    subject: Option<String>,
    senders: Vec<String>,
    reporter_domain: Option<String>,
    internal_claimed: bool,
    from_unparsed: bool,
}


pub fn triage(raw: &[u8], trusted: &[String], reporters: &ReporterPolicy) -> Result<Triage, TriageError> {
    triage_with(raw, trusted, reporters, &Limits::default())
}


pub fn triage_with(raw: &[u8], trusted: &[String], reporters: &ReporterPolicy, limits: &Limits) -> Result<Triage, TriageError> {
    triage_with_rule(raw, trusted, reporters, limits, &URL_RULE)
}


/// One reported message in, one record out; the rule is injected so a failing pattern is testable.
pub fn triage_with_rule(
    raw: &[u8],
    trusted: &[String],
    reporters: &ReporterPolicy,
    limits: &Limits,
    rule: &Result<Regex, regex::Error>,
) -> Result<Triage, TriageError> {
    check_policy(reporters)?;
    if raw.len() > limits.message_bytes {
        Err(TriageError::TooLarge)
    } else {
        parse_and_extract(raw, trusted, reporters, limits, rule)
    }
}


fn parse_and_extract(
    raw: &[u8],
    trusted: &[String],
    reporters: &ReporterPolicy,
    limits: &Limits,
    rule: &Result<Regex, regex::Error>,
) -> Result<Triage, TriageError> {
    let scanned = scan(raw, limits);
    let root = parse_message(&scanned.usable).ok_or(TriageError::Unparsable)?;
    let mut counts = Counts::default();
    note_scan(&mut counts, &scanned);
    let chain = open_chain(root, limits, &mut counts);
    let domains = domain_set(reporters);
    let context = Context {
        trusted,
        limits,
        rule,
        reporters,
        domains: &domains,
        has_attached: chain.len() > 1,
    };
    let start = Triage { counts, ..Triage::default() };
    Ok(chain
        .iter()
        .enumerate()
        .fold(start, |record, (index, message)| read_level(record, index, message, &context)))
}


fn note_scan(counts: &mut Counts, scanned: &Scan<'_>) {
    counts.scan_cut += usize::from(scanned.cut);
    counts.nested_refused += scanned.refused;
    counts.scan_lost_bytes += scanned.lost_bytes;
    counts.scan_lost_part = counts.scan_lost_part.or(scanned.lost_part);
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
        note_scan(counts, &scanned);
        parse_message(&scanned.usable).map(Message::into_owned)
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


/// The raw header value bytes, never the decoded ones; `None` when the name is not found at the recorded offset.
fn raw_bytes<'a>(message: &'a Message<'_>, header: &Header<'_>) -> Option<&'a [u8]> {
    let base = message.parts.first().map_or(0, |root| root.offset_header) as usize;
    let raw = message.raw_message();
    let relative = |offset: u32| (offset as usize).checked_sub(base);
    let name = header.name().as_bytes();
    let name_found = relative(header.offset_field)
        .and_then(|start| raw.get(start..start.saturating_add(name.len())))
        .is_some_and(|found| found.eq_ignore_ascii_case(name));
    let value = relative(header.offset_start)
        .zip(relative(header.offset_end))
        .and_then(|(start, end)| raw.get(start..end));
    value.filter(|_| name_found)
}


/// The raw header value as text, never the decoded one: an RFC 2047 word in a property could decode into a semicolon and a fake result.
fn raw_value<'a>(message: &'a Message<'_>, header: &Header<'_>) -> Option<&'a str> {
    raw_bytes(message, header).map(std::str::from_utf8).and_then(Result::ok)
}


fn authentication(message: &Message<'_>, context: &Context<'_>, counts: &mut Counts) -> (AuthVerdicts, Vec<Vec<String>>) {
    let limits = context.limits;
    let found: Vec<&Header<'_>> = header_slice(message, limits).iter().filter(|header| is_auth_header(header)).collect();
    let oversized = found.iter().filter(|header| header_bytes(header) > limits.header_bytes).count();
    counts.headers_skipped += oversized;
    let texts: Vec<Option<&str>> = found
        .iter()
        .filter(|header| header_bytes(header) <= limits.header_bytes)
        .map(|header| raw_value(message, header))
        .collect();
    verdicts_with_from(&texts, context.trusted, oversized > 0, counts)
}


/// An attached message's `Authentication-Results` is never trusted: the MTA strips only the top-level headers.
fn nested_auth(message: &Message<'_>, limits: &Limits, counts: &mut Counts) -> AuthVerdicts {
    counts.auth_nested_ignored += header_slice(message, limits).iter().filter(|header| is_auth_header(header)).count();
    AuthVerdicts {
        reason: Some(ATTACHED_ORIGINAL.to_owned()),
        ..AuthVerdicts::default()
    }
}


fn domain_of(address: &str) -> Option<&str> {
    address.rsplit_once('@').map(|(_, domain)| domain)
}


fn addresses<'a>(value: &'a HeaderValue<'_>) -> Vec<&'a str> {
    match value {
        HeaderValue::Address(Address::List(list)) => list.iter().filter_map(|addr| addr.address.as_deref()).collect(),
        HeaderValue::Address(Address::Group(groups)) => groups
            .iter()
            .flat_map(|group| group.addresses.iter())
            .filter_map(|addr| addr.address.as_deref())
            .collect(),
        _ => Vec::new(),
    }
}


fn entries<'a>(value: &'a HeaderValue<'_>) -> Vec<Option<&'a str>> {
    match value {
        HeaderValue::Address(Address::List(list)) => list.iter().map(|addr| addr.address.as_deref()).collect(),
        HeaderValue::Address(Address::Group(groups)) => groups
            .iter()
            .flat_map(|group| group.addresses.iter())
            .map(|addr| addr.address.as_deref())
            .collect(),
        _ => Vec::new(),
    }
}


fn from_headers<'a, 'b>(headers: &'a [Header<'b>]) -> Vec<&'a Header<'b>> {
    headers.iter().filter(|header| header.name().eq_ignore_ascii_case(FROM_HEADER)).collect()
}


/// Every address of every `From` header, cleaned, at most `MAX_FROM_ADDRESSES`; the rest is counted.
fn from_addresses(headers: &[Header<'_>], limits: &Limits, counts: &mut Counts) -> Vec<String> {
    let (small, oversized): (Vec<&Header<'_>>, Vec<&Header<'_>>) = from_headers(headers)
        .into_iter()
        .partition(|header| header_bytes(header) <= limits.header_bytes);
    counts.headers_skipped += oversized.len();
    let all: Vec<&str> = small.into_iter().flat_map(|header| addresses(header.value())).collect();
    counts.addresses_refused += all.len().saturating_sub(MAX_FROM_ADDRESSES);
    all.into_iter()
        .take(MAX_FROM_ADDRESSES)
        .filter_map(|address| clean_address(address, limits.address_bytes, counts))
        .collect()
}


/// The reporter's domain: the part after the last `@` of the one address of the one `From` header, never a group.
fn reporter_domain(headers: &[Header<'_>], senders: &[String]) -> Option<String> {
    let single = matches!(
        from_headers(headers).as_slice(),
        [only] if matches!(only.value(), HeaderValue::Address(Address::List(list)) if list.len() == 1)
    );
    match (single, senders) {
        (true, [one]) => domain_of(one).filter(|domain| is_strict_domain(domain)).map(str::to_ascii_lowercase),
        _ => None,
    }
}


/// An address is internal when its domain, trimmed and without one trailing dot, is in the set.
fn is_internal_address(address: &str, domains: &HashSet<String>) -> bool {
    domain_of(address).is_some_and(|domain| {
        let trimmed = domain.trim();
        domains.contains(&trimmed.strip_suffix('.').unwrap_or(trimmed).to_ascii_lowercase())
    })
}


fn counted_entries<'a>(headers: &'a [Header<'_>], limits: &Limits) -> Vec<Option<&'a str>> {
    from_headers(headers)
        .into_iter()
        .filter(|header| header_bytes(header) <= limits.header_bytes)
        .flat_map(|header| entries(header.value()))
        .collect()
}


/// A plain address is exactly one `@`, a non-empty local part and a strict domain (LDH, two labels, no trailing dot).
pub fn is_plain_address(address: &str) -> bool {
    let mut parts = address.split('@');
    let (local, domain, extra) = (parts.next(), parts.next(), parts.next());
    extra.is_none() && local.is_some_and(|text| !text.is_empty()) && domain.is_some_and(is_strict_domain)
}


fn usable_address(entry: &Option<&str>, limits: &Limits) -> bool {
    entry.is_some_and(|address| !is_refused_address(address, limits.address_bytes) && is_plain_address(address))
}


/// A From header read as text, an entry with no address, too many entries or an address that is refused or not plain: uncertain.
fn from_unparsed(headers: &[Header<'_>], entries: &[Option<&str>], limits: &Limits, forced: bool) -> bool {
    let from = from_headers(headers);
    let dropped = from.iter().any(|header| header_bytes(header) > limits.header_bytes);
    let not_address = from.iter().any(|header| !matches!(header.value(), HeaderValue::Address(_)));
    let empty = !from.is_empty() && entries.is_empty();
    let unusable = entries.len() > MAX_FROM_ADDRESSES || !entries.iter().all(|entry| usable_address(entry, limits));
    forced || dropped || not_address || empty || unusable
}


/// The byte scan of every `From` value inside the header limit; a value `read` cannot give back raw is counted and claims.
pub fn claim_from_raw(
    message: &Message<'_>,
    headers: &[Header<'_>],
    domains: &HashSet<String>,
    read: RawReadFn,
    counts: &mut Counts,
) -> (bool, bool) {
    from_headers(headers).into_iter().fold((false, false), |(claimed, unreadable), header| {
        let found = read(message, header).map(|bytes| claim_scan(bytes, domains));
        counts.claim_unreadable += usize::from(found.is_none());
        counts.claim_exhausted += usize::from(found.is_some_and(|scan| scan.exhausted));
        (claimed || found.is_none_or(|scan| scan.claimed), unreadable || found.is_none())
    })
}


fn header_facts(message: &Message<'_>, context: &Context<'_>, counts: &mut Counts) -> Facts {
    let limits = context.limits;
    counts.headers_skipped += message.headers().len().saturating_sub(limits.headers);
    counts.parts_skipped += message.parts.len().saturating_sub(limits.parts);
    let headers = header_slice(message, limits);
    let senders = from_addresses(headers, limits, counts);
    let parsed = counted_entries(headers, limits);
    let cut = message.headers().len() > limits.headers;
    let (scan_claim, unreadable) = claim_from_raw(message, headers, context.domains, raw_bytes, counts);
    let mut counted_above = Counts::default();
    Facts {
        sender: address_header(headers, FROM_HEADER, limits, &mut counted_above),
        return_path: address_header(headers, RETURN_PATH_HEADER, limits, counts),
        subject: find_header(headers, SUBJECT_HEADER, limits, counts)
            .and_then(|header| header.value().as_text())
            .map(|text| clean(text, limits.subject_chars, counts)),
        reporter_domain: reporter_domain(headers, &senders),
        internal_claimed: scan_claim || parsed.iter().flatten().any(|address| is_internal_address(address, context.domains)),
        from_unparsed: from_unparsed(headers, &parsed, limits, [cut, unreadable].contains(&true)),
        senders,
    }
}


fn internal_reason(domain: &str, auth: &AuthVerdicts, pass_from: &[Vec<String>]) -> String {
    let matching = pass_from
        .iter()
        .all(|values| !values.is_empty() && values.iter().all(|value| value == domain));
    match (auth.dmarc == PASS, matching) {
        (false, _) => format!("{REPORTER_DMARC_PREFIX}{}", auth.dmarc),
        (true, false) => REPORTER_DMARC_MISMATCH.to_owned(),
        (true, true) => REPORTER_FORWARD.to_owned(),
    }
}


fn reporter_reason(domain: Option<&str>, auth: &AuthVerdicts, pass_from: &[Vec<String>], context: &Context<'_>, counts: &mut Counts) -> String {
    match domain {
        None => REPORTER_FROM_AMBIGUOUS.to_owned(),
        Some(listed) if !is_internal(context.reporters, listed) => REPORTER_EXTERNAL.to_owned(),
        Some(listed) => {
            let reason = internal_reason(listed, auth, pass_from);
            counts.reporter_unverified += usize::from(reason != REPORTER_FORWARD);
            reason
        }
    }
}


/// Level 0: the reporter's forward or the reported message itself; sets the original level and the inline-forward verdict.
fn decide_original(record: &mut Triage, auth: &AuthVerdicts, pass_from: &[Vec<String>], facts: &Facts, context: &Context<'_>) {
    let reason = reporter_reason(facts.reporter_domain.as_deref(), auth, pass_from, context, &mut record.counts);
    let forward = reason == REPORTER_FORWARD;
    record.original_level = match (forward, context.has_attached) {
        (false, _) => Some(0),
        (true, true) => Some(1),
        (true, false) => None,
    };
    record.reporter_auth = forward.then(|| auth.clone());
    if record.original_level.is_none() {
        record.auth = AuthVerdicts {
            reason: Some(INLINE_FORWARD.to_owned()),
            ..AuthVerdicts::default()
        };
    }
    record.reporter = reason;
}


fn level_auth(record: &mut Triage, index: usize, message: &Message<'_>, facts: &Facts, context: &Context<'_>) -> AuthVerdicts {
    if index == 0 {
        let (auth, pass_from) = authentication(message, context, &mut record.counts);
        decide_original(record, &auth, &pass_from, facts, context);
        auth
    } else {
        nested_auth(message, context.limits, &mut record.counts)
    }
}


fn mark_uncertain(record: &mut Triage, reason: &str) {
    record.counts.original_uncertain += usize::from(!record.original_uncertain);
    record.original_uncertain = true;
    record.uncertain_reasons.push(reason.to_owned());
}


fn adopt_original(record: &mut Triage, info: &LevelInfo, facts: &Adoption) {
    record.sender = info.sender.clone();
    record.return_path = info.return_path.clone();
    record.subject = info.subject.clone();
    record.senders = info.senders.clone();
    record.auth = info.auth.clone();
    record.internal_claimed = facts.internal_claimed;
    record.counts.internal_claimed += usize::from(facts.internal_claimed);
    let mismatch = info.level == 0 && record.reporter == REPORTER_DMARC_MISMATCH;
    record.original_source = Some(if info.level == 0 { SOURCE_REPORTED } else { SOURCE_ATTACHED }.to_owned());
    if info.level != 0 {
        mark_uncertain(record, UNCERTAIN_ATTACHED_CLAIM);
    }
    if mismatch {
        mark_uncertain(record, UNCERTAIN_DMARC_MISMATCH);
    }
    if info.level == 0 && facts.internal_claimed {
        mark_uncertain(record, UNCERTAIN_INTERNAL_UNAUTHENTICATED);
    }
    if facts.from_unparsed {
        mark_uncertain(record, UNCERTAIN_FROM_UNPARSED);
    }
}


fn read_level(mut record: Triage, index: usize, message: &Message<'_>, context: &Context<'_>) -> Triage {
    let facts = header_facts(message, context, &mut record.counts);
    let auth = level_auth(&mut record, index, message, &facts, context);
    let adoption = Adoption {
        internal_claimed: facts.internal_claimed,
        from_unparsed: facts.from_unparsed,
    };
    let info = LevelInfo {
        level: index,
        sender: facts.sender,
        return_path: facts.return_path,
        subject: facts.subject,
        senders: facts.senders,
        auth,
    };
    if record.original_level == Some(index) {
        adopt_original(&mut record, &info, &adoption);
    }
    let known = std::mem::take(&mut record.urls);
    record.urls = collect_urls(message, index, context, known, &mut record.counts);
    let room = context.limits.attachments.saturating_sub(record.attachments.len());
    let listed = list_attachments(message, index, context.limits, room, &mut record.counts);
    record.attachments.extend(listed);
    record.levels.push(info);
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
