use crate::fetch_error::{BodyFailure, FetchError};
use crate::fetch_model::{FetchEnv, FetchSource, HttpRequest, ListedObject, Listing, Page, Pending, Reading, Walk};
use percent_encoding::percent_decode_str;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use rusty_s3::{Bucket, Credentials, S3Action};
use std::iter::from_fn;
use std::mem::take;
use std::time::Duration;
use url::Url;


pub const MAX_LIST_PAGES_PER_ROUND: usize = 10;


pub const MAX_LIST_BYTES: u64 = 4_194_304;


pub const MAX_KEYS_PER_PAGE: usize = 1000;


pub const MAX_KEY_BYTES: usize = 1024;


pub const MAX_TOKEN_BYTES: usize = 2048;


pub const MAX_XML_DEPTH: usize = 6;


pub const MAX_ETAG_BYTES: usize = 128;


/// The ledger stores the size as a `bigint`: a larger one skips that object alone.
pub const MAX_OBJECT_SIZE: u64 = i64::MAX as u64;


pub const PRESIGN_SECONDS: u64 = 60;


pub const HTTP_OK_FIRST: u16 = 200;


pub const HTTP_OK_LAST: u16 = 299;


pub const CONTENTS_OPEN: &str = "<Contents>";


pub const ROOT: &str = "ListBucketResult";


pub const CONTENTS: &str = "Contents";


pub fn malformed<Cause>(_cause: Cause) -> FetchError {
    FetchError::ListMalformed
}


pub fn open_bucket(source: &FetchSource) -> Result<Bucket, FetchError> {
    let endpoint = Url::parse(&source.endpoint).map_err(|_refused| FetchError::Bucket)?;
    Bucket::new(endpoint, rusty_s3::UrlStyle::Path, source.bucket.clone(), source.region.clone()).map_err(|_refused| FetchError::Bucket)
}


/// One GET through the injected HTTP step; only a 2xx answer counts, a redirect is a failure.
pub fn get_body(env: &FetchEnv<'_>, source: &FetchSource, url: String, max_response: u64) -> Result<Vec<u8>, BodyFailure> {
    let request = HttpRequest {
        url,
        max_response,
        ca_file: source.ca_file.clone(),
        timeout: Duration::from_millis(source.timeout_ms),
    };
    let response = (env.http)(&request).map_err(|failure| BodyFailure::Transport(failure.0))?;
    if (HTTP_OK_FIRST..=HTTP_OK_LAST).contains(&response.status) {
        Ok(response.body)
    } else {
        Err(BodyFailure::Status(response.status))
    }
}


/// A `GetObject` on the empty key is the bucket URL itself; the query turns it into a `ListObjectsV2` request (xml parsing of rusty-s3 is not used).
pub fn page_url(source: &FetchSource, bucket: &Bucket, credentials: &Credentials, token: Option<&str>, start_after: Option<&str>) -> String {
    let mut action = bucket.get_object(Some(credentials), "");
    let query = action.query_mut();
    query.insert("list-type", "2");
    query.insert("encoding-type", "url");
    query.insert("max-keys", MAX_KEYS_PER_PAGE.to_string());
    query.insert("prefix", source.prefix.as_str());
    if let Some(found) = token {
        query.insert("continuation-token", found);
    } else if let Some(resume) = start_after {
        query.insert("start-after", resume);
    }
    action.sign(Duration::from_secs(PRESIGN_SECONDS)).to_string()
}


pub fn text_of(state: &mut Reading) -> String {
    take(&mut state.text)
}


pub fn open(state: &mut Reading, start: &BytesStart<'_>) -> Result<(), FetchError> {
    let name = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
    state.text.clear();
    state.path.push(name);
    let names: Vec<&str> = state.path.iter().map(String::as_str).collect();
    let depth_ok = names.len() <= MAX_XML_DEPTH;
    let rooted = names.first() == Some(&ROOT);
    let too_many = names.as_slice() == [ROOT, CONTENTS] && state.contents.len() >= MAX_KEYS_PER_PAGE;
    state.seen_root |= names.as_slice() == [ROOT];
    if too_many {
        Err(FetchError::ListTooManyKeys)
    } else if depth_ok && rooted {
        Ok(())
    } else {
        Err(FetchError::ListMalformed)
    }
}


pub fn close(state: &mut Reading) -> Result<(), FetchError> {
    let text = text_of(state);
    let view: Vec<&str> = state.path.iter().map(String::as_str).collect();
    match view.as_slice() {
        [ROOT, CONTENTS, "Key"] => state.pending.key = Some(text),
        [ROOT, CONTENTS, "ETag"] => state.pending.etag = Some(text),
        [ROOT, CONTENTS, "Size"] => state.pending.size = text.parse::<u64>().ok().filter(|size| *size <= MAX_OBJECT_SIZE),
        [ROOT, CONTENTS] => state.contents.push(take(&mut state.pending)),
        [ROOT, "IsTruncated"] => state.truncated = text == "true",
        [ROOT, "NextContinuationToken"] => state.token = Some(text),
        [ROOT, "EncodingType"] => state.url_encoded = text == "url",
        _ => {}
    }
    state.path.pop();
    Ok(())
}


pub fn append_reference(state: &mut Reading, name: &str, character: Option<char>) -> Result<(), FetchError> {
    let resolved = match (character, resolve_predefined_entity(name)) {
        (Some(found), _) => Some(found.to_string()),
        (None, Some(entity)) => Some(entity.to_owned()),
        (None, None) => None,
    };
    resolved.map(|text| state.text.push_str(&text)).ok_or(FetchError::ListMalformed)
}


pub fn step(state: &mut Reading, event: Event<'_>) -> Result<(), FetchError> {
    match event {
        Event::Start(start) => open(state, &start),
        Event::Empty(start) => open(state, &start).and_then(|()| close(state)),
        Event::End(_) => close(state),
        Event::Text(text) => {
            state.text.push_str(&text.decode().map_err(malformed)?);
            Ok(())
        }
        Event::GeneralRef(reference) => append_reference(
            state,
            &reference.decode().map_err(malformed)?,
            reference.resolve_char_ref().map_err(malformed)?,
        ),
        _ => Ok(()),
    }
}


/// Percent-decodes a key the way the server encoded it (`+` is a space); a key that is not UTF-8 after decoding is refused.
pub fn decode_key(raw: &str) -> Option<String> {
    percent_decode_str(&raw.replace('+', " "))
        .decode_utf8()
        .ok()
        .map(|decoded| decoded.into_owned())
}


/// A key under the prefix, at most `MAX_KEY_BYTES`, printable ASCII without a backslash, no empty, `.` or `..` segment, ending in `.csv` or `.csv.gz`.
pub fn key_ok(key: &str, prefix: &str) -> bool {
    key.len() <= MAX_KEY_BYTES
        && key.starts_with(prefix)
        && key.chars().all(|character| character.is_ascii_graphic() && character != '\\')
        && key.split('/').all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && (key.ends_with(".csv") || key.ends_with(".csv.gz"))
}


/// The ETag is part of the ledger key: at most `MAX_ETAG_BYTES` of printable ASCII.
pub fn etag_ok(etag: &str) -> bool {
    etag.len() <= MAX_ETAG_BYTES && etag.chars().all(|character| character.is_ascii_graphic())
}


pub fn admit(content: Pending, url_encoded: bool, prefix: &str) -> Option<ListedObject> {
    let raw = content.key?;
    let key = if url_encoded { decode_key(&raw)? } else { raw };
    key_ok(&key, prefix).then_some(())?;
    let etag = content.etag.filter(|found| etag_ok(found))?;
    Some(ListedObject {
        key,
        etag,
        size: content.size?,
    })
}


/// A key the next round can resume after: at most `MAX_KEY_BYTES` of printable ASCII.
pub fn cursor_ok(key: &str) -> bool {
    key.len() <= MAX_KEY_BYTES && key.chars().all(|character| character.is_ascii_graphic())
}


pub fn decode_cursor(raw: &str, url_encoded: bool) -> Option<String> {
    if url_encoded {
        decode_key(raw)
    } else {
        Some(raw.to_owned())
    }
}


/// The last key of the page, whatever the filters say of it, that can go back into a `start-after` query.
pub fn cursor_key(contents: &[Pending], url_encoded: bool) -> Option<String> {
    contents
        .iter()
        .rev()
        .filter_map(|content| content.key.as_deref())
        .filter_map(|raw| decode_cursor(raw, url_encoded))
        .find(|key| cursor_ok(key))
}


/// The literal `<Contents>` count is only an early exit; the walk itself refuses the element past `MAX_KEYS_PER_PAGE` whatever its spelling.
pub fn parse_page(text: &str, prefix: &str) -> Result<Page, FetchError> {
    if text.matches(CONTENTS_OPEN).count() > MAX_KEYS_PER_PAGE {
        Err(FetchError::ListTooManyKeys)
    } else {
        let mut reader = Reader::from_str(text);
        let mut state = Reading::default();
        from_fn(|| match reader.read_event() {
            Ok(Event::Eof) => None,
            other => Some(other),
        })
        .try_for_each(|event| step(&mut state, event.map_err(malformed)?))?;
        finish(state, prefix)
    }
}


pub fn finish(state: Reading, prefix: &str) -> Result<Page, FetchError> {
    let token_ok = state.token.as_ref().is_none_or(|token| token.len() <= MAX_TOKEN_BYTES);
    let complete = state.seen_root && state.path.is_empty() && token_ok && !(state.truncated && state.token.is_none());
    if complete {
        let total = state.contents.len();
        let last_key = cursor_key(&state.contents, state.url_encoded);
        let objects: Vec<ListedObject> = state
            .contents
            .into_iter()
            .filter_map(|content| admit(content, state.url_encoded, prefix))
            .collect();
        Ok(Page {
            skipped: total - objects.len(),
            objects,
            last_key,
            next_token: state.token.filter(|_| state.truncated),
        })
    } else {
        Err(FetchError::ListMalformed)
    }
}


/// One page: the signed request, the body under `MAX_LIST_BYTES`, then the parse.
pub fn list_page(
    env: &FetchEnv<'_>,
    source: &FetchSource,
    bucket: &Bucket,
    credentials: &Credentials,
    token: Option<&str>,
    start_after: Option<&str>,
) -> Result<Page, FetchError> {
    let body = get_body(env, source, page_url(source, bucket, credentials, token, start_after), MAX_LIST_BYTES + 1)?;
    if body.len() as u64 > MAX_LIST_BYTES {
        Err(FetchError::ListTooLarge)
    } else {
        parse_page(&String::from_utf8(body).map_err(malformed)?, &source.prefix)
    }
}


pub fn walk_step(
    env: &FetchEnv<'_>,
    source: &FetchSource,
    bucket: &Bucket,
    credentials: &Credentials,
    start_after: Option<&str>,
    walk: Walk,
) -> Result<Walk, FetchError> {
    if walk.done {
        Ok(walk)
    } else {
        let page = list_page(env, source, bucket, credentials, walk.token.as_deref(), start_after)?;
        Ok(Walk {
            done: page.next_token.is_none(),
            token: page.next_token,
            last_key: page.last_key.or(walk.last_key),
            objects: walk.objects.into_iter().chain(page.objects).collect(),
            skipped: walk.skipped + page.skipped,
        })
    }
}


/// At most `MAX_LIST_PAGES_PER_ROUND` pages from `start_after`; a listing still truncated after them is `incomplete` and names its last key.
pub fn list_objects(
    env: &FetchEnv<'_>,
    source: &FetchSource,
    bucket: &Bucket,
    credentials: &Credentials,
    start_after: Option<&str>,
) -> Result<Listing, FetchError> {
    let walk = (0..MAX_LIST_PAGES_PER_ROUND).try_fold(Walk::default(), |walk, _page| {
        walk_step(env, source, bucket, credentials, start_after, walk)
    })?;
    Ok(Listing {
        incomplete: !walk.done,
        last_key: walk.last_key.or(start_after.map(str::to_owned)),
        objects: walk.objects,
        skipped_key: walk.skipped,
    })
}
