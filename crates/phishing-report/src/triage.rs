use crate::auth::{oversized_untrusted, verdicts_with_from, PASS};
use crate::claim::{claim_scan, domain_set};
use crate::error::TriageError;
use crate::limits::{Limits, MAX_FROM_ADDRESSES};
use crate::model::{AttachmentInfo, AuthVerdicts, Counts, LevelInfo, ReporterPolicy, Shapes, Triage, UrlHit, UrlIndex};
use crate::policy::{check_policy, is_internal, is_strict_domain};
use crate::scan::{scan, Scan};
use crate::shapes::has_reference;
use crate::text::{clean, clean_address, is_refused_address};
use crate::types::RawReadFn;
use crate::urls::{collect_indexed, html_text, index_from, URL_RULE};
use data_encoding::HEXLOWER;
use encoding_rs::{Encoding, ISO_2022_JP, REPLACEMENT, X_USER_DEFINED};
use mail_parser::decoders::charsets::map::charset_decoder;
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
    read: RawReadFn,
    has_attached: bool,
    scan_refused: bool,
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
    triage_with_reader(raw, trusted, reporters, limits, rule, raw_bytes)
}


/// As `triage_with_rule`, with the raw header read injected so a value that cannot be read back is testable.
pub fn triage_with_reader(
    raw: &[u8],
    trusted: &[String],
    reporters: &ReporterPolicy,
    limits: &Limits,
    rule: &Result<Regex, regex::Error>,
    read: RawReadFn,
) -> Result<Triage, TriageError> {
    check_policy(reporters)?;
    if raw.len() > limits.message_bytes {
        Err(TriageError::TooLarge)
    } else {
        parse_and_extract(raw, trusted, reporters, limits, rule, read)
    }
}


fn parse_and_extract(
    raw: &[u8],
    trusted: &[String],
    reporters: &ReporterPolicy,
    limits: &Limits,
    rule: &Result<Regex, regex::Error>,
    read: RawReadFn,
) -> Result<Triage, TriageError> {
    let scanned = scan(raw, limits);
    let root = parse_message(&scanned.usable).ok_or(TriageError::Unparsable)?;
    let mut counts = Counts::default();
    note_scan(&mut counts, &scanned);
    let chain = open_chain(root, limits, &mut counts);
    let domains = domain_set(reporters);
    let scan_refused = counts.nested_refused > 0 || counts.scan_lost_bytes > 0;
    let context = Context {
        trusted,
        limits,
        rule,
        reporters,
        domains: &domains,
        read,
        has_attached: chain.len() > 1,
        scan_refused,
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
    let (big, small): (Vec<&Header<'_>>, Vec<&Header<'_>>) = found.iter().partition(|header| header_bytes(header) > limits.header_bytes);
    let untrusted = big
        .iter()
        .filter(|header| oversized_untrusted(raw_bytes(message, header), limits.header_bytes, context.trusted))
        .count();
    counts.headers_skipped += big.len();
    counts.auth_oversized_untrusted += untrusted;
    let texts: Vec<Option<&str>> = small.iter().map(|header| raw_value(message, header)).collect();
    verdicts_with_from(&texts, context.trusted, big.len() > untrusted, counts)
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


fn named_headers<'a, 'b>(headers: &'a [Header<'b>], name: &str) -> Vec<&'a Header<'b>> {
    headers.iter().filter(|header| header.name().eq_ignore_ascii_case(name)).collect()
}


fn from_headers<'a, 'b>(headers: &'a [Header<'b>]) -> Vec<&'a Header<'b>> {
    named_headers(headers, FROM_HEADER)
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


/// No From header, a From header read as text, an entry with no address, too many entries or an address that is refused or not plain: uncertain.
fn from_unparsed(headers: &[Header<'_>], entries: &[Option<&str>], limits: &Limits, forced: bool) -> bool {
    let from = from_headers(headers);
    let dropped = from.iter().any(|header| header_bytes(header) > limits.header_bytes);
    let not_address = from.iter().any(|header| !matches!(header.value(), HeaderValue::Address(_)));
    let unusable = entries.len() > MAX_FROM_ADDRESSES || !entries.iter().all(|entry| usable_address(entry, limits));
    forced || dropped || not_address || unusable
}


/// The byte scan of every value of the named header inside the header limit; a value `read` cannot give back raw is counted and claims.
pub fn claim_from_raw(
    message: &Message<'_>,
    headers: &[Header<'_>],
    name: &str,
    domains: &HashSet<String>,
    read: RawReadFn,
    counts: &mut Counts,
) -> (bool, bool) {
    named_headers(headers, name)
        .into_iter()
        .fold((false, false), |(claimed, unreadable), header| {
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
    let (scan_claim, unreadable) = claim_from_raw(message, headers, FROM_HEADER, context.domains, context.read, counts);
    let (path_claim, _) = claim_from_raw(message, headers, RETURN_PATH_HEADER, context.domains, context.read, counts);
    let mut counted_above = Counts::default();
    let sender = address_header(headers, FROM_HEADER, limits, &mut counted_above);
    let no_sender = sender.is_none();
    Facts {
        sender,
        return_path: address_header(headers, RETURN_PATH_HEADER, limits, counts),
        subject: find_header(headers, SUBJECT_HEADER, limits, counts)
            .and_then(|header| header.value().as_text())
            .map(|text| clean(text, limits.subject_chars, counts)),
        reporter_domain: reporter_domain(headers, &senders),
        internal_claimed: scan_claim || path_claim || parsed.iter().flatten().any(|address| is_internal_address(address, context.domains)),
        from_unparsed: from_unparsed(headers, &parsed, limits, cut || unreadable || no_sender),
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


const URL_HOST_UNREAD: &str = "url_host_unread";


const URL_USERINFO_SPLIT: &str = "url_userinfo_split";


const URL_HOST_AMBIGUOUS: &str = "url_host_ambiguous";


const URL_CAP_REACHED: &str = "url_cap_reached";


const SCAN_REFUSED: &str = "scan_refused";


const PARTS_SKIPPED: &str = "parts_skipped";


const NESTING_CUT: &str = "nesting_cut";


const MESSAGES_UNOPENED: &str = "messages_unopened";


const UTF8_LABELS: [&str; 6] = ["utf8", "utf_8", "unicode11utf8", "unicode20utf8", "x_unicode20utf8", "unicode_1_1_utf_8"];


const CHARSET_UNDECODED: &str = "charset_undecoded";


const ESCAPE_CHARACTER: char = '\u{1B}';


const LOST_BYTE_CHARACTERS: [char; 2] = ['\u{FFFD}', '\u{0}'];


const META_SNIFF_BYTES: usize = 1024;


const META_TAG: &str = "<meta";


const CHARSET_WORD: &str = "charset";


const ASCII_LABELS: [&str; 2] = ["us_ascii", "ascii"];


const CONTENT_TYPE_HEADER: &str = "content-type";


const CONTINUATION_MARKER: &str = "charset*";


const FIRST_CONTINUATION: &str = "charset*0";


fn mark_once(record: &mut Triage, flagged: bool, reason: &str) {
    if flagged && !record.uncertain_reasons.iter().any(|found| found == reason) {
        mark_uncertain(record, reason);
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
    let mut urls_index = index_from(&known, std::mem::take(&mut record.refused_hosts));
    record.urls = collect_urls(message, index, context, known, &mut urls_index, &mut record.counts);
    record.refused_hosts = urls_index.hosts;
    let unread = record.counts.url_host_unread > 0;
    let split = record.counts.url_userinfo_split > 0;
    let ambiguous = record.counts.url_host_ambiguous > 0;
    let capped = record.counts.url_cap_reached > 0;
    mark_once(&mut record, unread, URL_HOST_UNREAD);
    mark_once(&mut record, split, URL_USERINFO_SPLIT);
    mark_once(&mut record, ambiguous, URL_HOST_AMBIGUOUS);
    mark_once(&mut record, capped, URL_CAP_REACHED);
    mark_once(&mut record, context.scan_refused, SCAN_REFUSED);
    let skipped = record.counts.parts_skipped > 0;
    mark_once(&mut record, skipped, PARTS_SKIPPED);
    let cut = record.counts.nesting_cut > 0;
    let unopened = record.counts.messages_unopened > 0;
    mark_once(&mut record, cut, NESTING_CUT);
    mark_once(&mut record, unopened, MESSAGES_UNOPENED);
    let undecoded = record.counts.charset_undecoded > 0;
    mark_once(&mut record, undecoded, CHARSET_UNDECODED);
    let room = context.limits.attachments.saturating_sub(record.attachments.len());
    let listed = list_attachments(message, index, context.limits, room, &mut record.counts);
    record.attachments.extend(listed);
    record.levels.push(info);
    record
}


fn charset_label<'a>(part: &'a MessagePart<'_>) -> Option<&'a str> {
    part.content_type().and_then(|content_type| content_type.attribute("charset"))
}


fn encoding_of(label: &str) -> Option<&'static Encoding> {
    Encoding::for_label(label.replace('_', "-").as_bytes())
}


fn is_replacement_label(label: &str) -> bool {
    encoding_of(label).is_some_and(|found| found == REPLACEMENT || found == X_USER_DEFINED)
}


fn is_iso_2022_jp(label: &str) -> bool {
    encoding_of(label).is_some_and(|found| found == ISO_2022_JP)
}


fn is_undecoded(message: &Message<'_>, part: &MessagePart<'_>, text: &str) -> bool {
    let label = charset_label(part);
    let unknown_label = label.is_some_and(|name| (charset_decoder(name.as_bytes()).is_none() && !is_utf8_label(name)) || is_replacement_label(name));
    let escape_allowed = label.is_some_and(is_iso_2022_jp);
    let unlabelled_meta = label.is_none() && has_foreign_meta_charset(text);
    unknown_label || has_lost_bytes(text, escape_allowed) || has_duplicate_charset(part) || unlabelled_meta || has_orphan_continuation(message, part)
}


fn has_lost_bytes(text: &str, escape_allowed: bool) -> bool {
    text.chars()
        .any(|character| LOST_BYTE_CHARACTERS.contains(&character) || (character == ESCAPE_CHARACTER && !escape_allowed))
}


fn has_duplicate_charset(part: &MessagePart<'_>) -> bool {
    part.content_type()
        .and_then(|content_type| content_type.attributes())
        .is_some_and(|attributes| attributes.iter().filter(|attribute| attribute.name.starts_with("charset")).count() > 1)
}


fn is_utf8_label(label: &str) -> bool {
    let folded = label.to_ascii_lowercase().replace('-', "_");
    UTF8_LABELS.contains(&folded.as_str())
}


fn is_plain_label(label: &str) -> bool {
    let folded = label.to_ascii_lowercase().replace('-', "_");
    is_utf8_label(label) || ASCII_LABELS.contains(&folded.as_str())
}


fn sniff_prefix(text: &str) -> String {
    let cut = (0..=META_SNIFF_BYTES.min(text.len())).rev().find(|index| text.is_char_boundary(*index));
    cut.and_then(|end| text.get(..end)).map_or_else(String::new, str::to_ascii_lowercase)
}


fn is_label_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
}


fn meta_label(tag: &str) -> Option<&str> {
    let declared = tag.split('>').next().unwrap_or(tag);
    declared.split_once(CHARSET_WORD).and_then(|(_, after)| {
        let value = after.trim_start().trim_start_matches('=').trim_start().trim_start_matches(['"', '\'']);
        value.split(|character: char| !is_label_character(character)).next()
    })
}


fn has_foreign_meta_charset(text: &str) -> bool {
    let prefix = sniff_prefix(text);
    prefix
        .split(META_TAG)
        .skip(1)
        .any(|tag| meta_label(tag).is_some_and(|label| !is_plain_label(label)))
}


fn has_orphan_continuation(message: &Message<'_>, part: &MessagePart<'_>) -> bool {
    part.headers()
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case(CONTENT_TYPE_HEADER))
        .filter_map(|header| raw_value(message, header))
        .map(|raw| raw.to_ascii_lowercase().split_whitespace().collect::<String>())
        .any(|compact| compact.contains(CONTINUATION_MARKER) && !compact.contains(FIRST_CONTINUATION))
}


fn collect_urls(
    message: &Message<'_>,
    level: usize,
    context: &Context<'_>,
    known: Vec<UrlHit>,
    urls_index: &mut UrlIndex,
    counts: &mut Counts,
) -> Vec<UrlHit> {
    let limits = context.limits;
    message.parts.iter().take(limits.parts).fold(known, |urls, part| {
        let oversized = part.len() > limits.part_bytes;
        match &part.body {
            PartType::Text(_) | PartType::Html(_) if oversized => {
                counts.parts_skipped += 1;
                urls
            }
            PartType::Text(markup) | PartType::Html(markup) => {
                counts.charset_undecoded += usize::from(is_undecoded(message, part, markup));
                let referenced = has_reference(markup);
                urls_index.shapes = if referenced { Shapes::Refuse } else { Shapes::Markup };
                let decoded = html_text(markup, counts);
                let listed = collect_indexed(context.rule, &decoded, level, limits, urls, urls_index, counts);
                urls_index.shapes = Shapes::Refuse;
                if referenced {
                    collect_indexed(context.rule, markup, level, limits, listed, urls_index, counts)
                } else {
                    listed
                }
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
