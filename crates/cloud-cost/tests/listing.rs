#[path = "common/fetch/types.rs"]
mod types;
#[path = "common/walk/types.rs"]
mod walk_types;


use cloud_cost::fetch_error::{FetchError, HttpClass, HttpFailure};
use cloud_cost::fetch_model::{FetchEnv, FetchSource, HttpResponse, ListedObject, Pending, DEFAULT_FETCH_TIMEOUT_MS, DEFAULT_MAX_OBJECTS};
use cloud_cost::listing::{
    admit, cursor_key, decode_key, etag_ok, get_body, key_ok, list_objects, list_page, open_bucket, page_url, parse_page, MAX_ETAG_BYTES,
    MAX_KEYS_PER_PAGE, MAX_KEY_BYTES, MAX_LIST_BYTES, MAX_LIST_PAGES, MAX_OBJECT_SIZE, MAX_TOKEN_BYTES, MAX_XML_DEPTH,
};
use cloud_cost::model::Limits;
use rusty_s3::Credentials;
use std::cell::{Cell, RefCell};
use std::error::Error;
use types::{Reply, TestResult};
use url::Url;
use walk_types::Walked;


const PREFIX: &str = "p/";


const SIZE: u64 = 10;


const HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name>";


const TAIL: &str = "</ListBucketResult>";


const ENCODED: &str = "<EncodingType>url</EncodingType>";


const STATUS_ERROR: u16 = 503;


const TWO: usize = 2;


const FIVE: usize = 5;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const STATUS_OK: u16 = 200;


fn entry(key: &str, etag: &str, size: &str) -> String {
    format!("<Contents><Key>{key}</Key><ETag>&quot;{etag}&quot;</ETag><Size>{size}</Size></Contents>")
}


fn page(parts: &[&str]) -> String {
    format!("{HEAD}{ENCODED}{}{TAIL}", parts.concat())
}


fn source() -> FetchSource {
    FetchSource {
        id: "main".to_owned(),
        tenant: "acme".to_owned(),
        endpoint: "https://s3.example.test".to_owned(),
        region: "garage".to_owned(),
        bucket: "billing".to_owned(),
        prefix: PREFIX.to_owned(),
        credentials: "acme/s3.key".to_owned(),
        ca_file: None,
        max_objects_per_run: DEFAULT_MAX_OBJECTS,
        timeout_ms: DEFAULT_FETCH_TIMEOUT_MS,
    }
}


fn keys_of(text: &str) -> Result<Vec<String>, FetchError> {
    Ok(parse_page(text, PREFIX)?.objects.into_iter().map(|object| object.key).collect())
}


#[test]
fn a_page_lists_its_csv_objects_with_the_etag_unquoted_by_the_entity() -> TestResult {
    let text = page(&[&entry("p/a.csv", "abc", "10"), &entry("p/b.csv.gz", "def", "20")]);
    let parsed = parse_page(&text, PREFIX)?;
    assert_eq!(parsed.skipped, 0);
    assert_eq!(parsed.next_token, None);
    assert_eq!(
        parsed.objects.first(),
        Some(&ListedObject {
            key: "p/a.csv".to_owned(),
            etag: "\"abc\"".to_owned(),
            size: SIZE
        })
    );
    assert_eq!(parsed.objects.len(), TWO);
    Ok(())
}


#[test]
fn a_truncated_page_carries_its_token_and_a_complete_page_drops_it() -> TestResult {
    let truncated = page(&["<IsTruncated>true</IsTruncated><NextContinuationToken>tok&amp;1</NextContinuationToken>"]);
    assert_eq!(parse_page(&truncated, PREFIX)?.next_token, Some("tok&1".to_owned()));
    let complete = page(&["<IsTruncated>false</IsTruncated><NextContinuationToken>tok</NextContinuationToken>"]);
    assert_eq!(parse_page(&complete, PREFIX)?.next_token, None);
    let silent = page(&["<NextContinuationToken>tok</NextContinuationToken>"]);
    assert_eq!(parse_page(&silent, PREFIX)?.next_token, None);
    assert!(matches!(
        parse_page(&page(&["<IsTruncated>true</IsTruncated>"]), PREFIX),
        Err(FetchError::ListMalformed)
    ));
    Ok(())
}


#[test]
fn a_hostile_key_is_skipped_alone_and_counted() -> TestResult {
    let long = format!("p/{}.csv", "a".repeat(MAX_KEY_BYTES));
    let hostile = [
        "p/tool.exe",
        "other/x.csv",
        "p/../x.csv",
        "p/%2e%2e/x.csv",
        "p/a//b.csv",
        "p/./b.csv",
        "p/a%0ab.csv",
        "p/a%5cb.csv",
        "p/a+b.csv",
        "p/%ff.csv",
        long.as_str(),
    ];
    let entries: Vec<String> = hostile.iter().map(|key| entry(key, "e", "1")).collect();
    let good = entry("p/ok%2Bplus.csv", "e", "1");
    let text = page(&entries.iter().map(String::as_str).chain([good.as_str()]).collect::<Vec<_>>());
    let parsed = parse_page(&text, PREFIX)?;
    assert_eq!(parsed.skipped, hostile.len());
    assert_eq!(parsed.objects.len(), 1);
    assert_eq!(parsed.objects.first().map(|object| object.key.as_str()), Some("p/ok+plus.csv"));
    Ok(())
}


#[test]
fn an_incomplete_element_is_skipped_and_counted() -> TestResult {
    let no_key = "<Contents><ETag>e</ETag><Size>1</Size></Contents>";
    let no_etag = "<Contents><Key>p/a.csv</Key><Size>1</Size></Contents>";
    let no_size = "<Contents><Key>p/a.csv</Key><ETag>e</ETag></Contents>";
    let bad_size = "<Contents><Key>p/a.csv</Key><ETag>e</ETag><Size>many</Size></Contents>";
    let empty = "<Contents/>";
    let parsed = parse_page(&page(&[no_key, no_etag, no_size, bad_size, empty]), PREFIX)?;
    assert_eq!((parsed.objects.len(), parsed.skipped), (0, FIVE));
    Ok(())
}


#[test]
fn a_size_the_ledger_cannot_store_skips_that_object_alone() -> TestResult {
    let largest = entry("p/max.csv", "e", &MAX_OBJECT_SIZE.to_string());
    let beyond = entry("p/huge.csv", "e", &(MAX_OBJECT_SIZE + 1).to_string());
    let good = entry("p/ok.csv", "e", "1");
    let parsed = parse_page(&page(&[beyond.as_str(), largest.as_str(), good.as_str()]), PREFIX)?;
    let keys: Vec<&str> = parsed.objects.iter().map(|object| object.key.as_str()).collect();
    assert_eq!((keys, parsed.skipped), (vec!["p/max.csv", "p/ok.csv"], 1));
    assert_eq!(MAX_OBJECT_SIZE, u64::try_from(i64::MAX)?);
    Ok(())
}


#[test]
fn keys_are_taken_raw_without_the_url_encoding_element() -> TestResult {
    let text = format!("{HEAD}{}{TAIL}", entry("p/a%2Bb.csv", "e", "1"));
    assert_eq!(keys_of(&text)?, vec!["p/a%2Bb.csv".to_owned()]);
    Ok(())
}


#[test]
fn character_references_and_decls_are_read() -> TestResult {
    let text = page(&["<Contents><Key>p/a.csv</Key><ETag>&#65;</ETag><Size>1</Size></Contents>"]);
    assert_eq!(parse_page(&text, PREFIX)?.objects.first().map(|object| object.etag.as_str()), Some("A"));
    Ok(())
}


#[test]
fn malformed_pages_are_refused() -> TestResult {
    let nested = format!("{HEAD}{}1{}{TAIL}", "<a>".repeat(MAX_XML_DEPTH), "</a>".repeat(MAX_XML_DEPTH));
    let long_token = page(&[&format!(
        "<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>",
        "t".repeat(MAX_TOKEN_BYTES + 1)
    )]);
    let texts = [
        "<Error><Code>AccessDenied</Code></Error>".to_owned(),
        String::new(),
        format!("{HEAD}<Contents>"),
        format!("{HEAD}</Wrong>"),
        page(&["<Contents><Key>p/a.csv&bogus;</Key></Contents>"]),
        "<a><ListBucketResult/></a>".to_owned(),
        nested,
        long_token,
        "<ListBucketResult><Contents><Key>&#xZZ;</Key></Contents></ListBucketResult>".to_owned(),
    ];
    texts
        .iter()
        .for_each(|text| assert!(matches!(parse_page(text, PREFIX), Err(FetchError::ListMalformed)), "{text}"));
    Ok(())
}


#[test]
fn the_key_count_is_checked_before_the_parse() -> TestResult {
    let many = entry("p/a.csv", "e", "1").repeat(MAX_KEYS_PER_PAGE + 1);
    assert!(matches!(parse_page(&page(&[&many]), PREFIX), Err(FetchError::ListTooManyKeys)));
    let exact = entry("p/a.csv", "e", "1").repeat(MAX_KEYS_PER_PAGE);
    assert_eq!(
        parse_page(&page(&[&exact]), PREFIX).map(|parsed| parsed.objects.len()).ok(),
        Some(MAX_KEYS_PER_PAGE)
    );
    Ok(())
}


#[test]
fn key_helpers_decide_alone() -> TestResult {
    assert_eq!(decode_key("a+b%2Bc"), Some("a b+c".to_owned()));
    assert_eq!(decode_key("%ff"), None);
    assert!(key_ok("p/a.csv", PREFIX));
    assert!(key_ok("p/BILLING_PERIOD=2024-01/a.csv.gz", PREFIX));
    assert!(!key_ok("p/a.csv.zip", PREFIX));
    assert!(!key_ok("q/a.csv", PREFIX));
    assert!(!key_ok("p/a\u{3164}.csv", PREFIX));
    assert!(admit(Pending::default(), true, PREFIX).is_none());
    Ok(())
}


fn reply(status: u16, body: &str) -> Reply {
    Ok(HttpResponse {
        status,
        body: body.as_bytes().to_vec(),
    })
}


fn credentials() -> Credentials {
    Credentials::new("access", "secret")
}


#[test]
fn the_page_url_is_a_signed_list_request_for_the_prefix() -> TestResult {
    let bucket = open_bucket(&source())?;
    let first = Url::parse(&page_url(&source(), &bucket, &credentials(), None, None))?;
    let query: Vec<(String, String)> = first.query_pairs().into_owned().collect();
    assert_eq!(first.path(), "/billing/");
    assert!(query.contains(&("list-type".to_owned(), "2".to_owned())));
    assert!(query.contains(&("prefix".to_owned(), PREFIX.to_owned())));
    assert!(query.contains(&("max-keys".to_owned(), MAX_KEYS_PER_PAGE.to_string())));
    assert!(query.iter().any(|(name, _)| name == "X-Amz-Signature"));
    assert!(!query.iter().any(|(name, _)| name == "continuation-token"));
    let next = Url::parse(&page_url(&source(), &bucket, &credentials(), Some("tok en"), Some("p/ignored.csv")))?;
    assert!(next.query_pairs().any(|(name, value)| name == "continuation-token" && value == "tok en"));
    Ok(())
}


#[test]
fn a_bad_endpoint_is_refused() -> TestResult {
    let mut bad = source();
    bad.endpoint = "not a url".to_owned();
    assert!(matches!(open_bucket(&bad), Err(FetchError::Bucket)));
    bad.endpoint = "mailto:someone@example.test".to_owned();
    assert!(matches!(open_bucket(&bad), Err(FetchError::Bucket)));
    Ok(())
}


fn env_of<'a>(
    http: &'a cloud_cost::types::HttpFn<'a>,
    exec: &'a cloud_cost::types::ExecFn<'a>,
    load: &'a cloud_cost::types::LoadFn<'a>,
    limits: &'a Limits,
) -> FetchEnv<'a> {
    FetchEnv { http, exec, load, limits }
}


fn walk(replies: &dyn Fn(usize) -> Reply) -> Result<Walked, Box<dyn Error>> {
    Ok(walk_from(replies, None)?.0)
}


fn walk_from(replies: &dyn Fn(usize) -> Reply, start_after: Option<&str>) -> Result<(Walked, Vec<String>), Box<dyn Error>> {
    let calls = Cell::new(0);
    let urls = RefCell::new(Vec::new());
    let http = |request: &cloud_cost::fetch_model::HttpRequest| {
        urls.borrow_mut().push(request.url.clone());
        calls.set(calls.get() + 1);
        replies(calls.get() - 1)
    };
    let exec = |_sql: &str, _params: &[String]| Ok(Vec::new());
    let load = |_tenant: &str, _export: &cloud_cost::source::Export| Ok(cloud_cost::load::LoadOutcome::default());
    let limits = Limits::default();
    let env = env_of(&http, &exec, &load, &limits);
    let bucket = open_bucket(&source())?;
    let listing = list_objects(&env, &source(), &bucket, &credentials(), start_after);
    Ok(((listing, calls.get()), urls.into_inner()))
}


#[test]
fn pages_are_followed_by_token_until_the_last_one() -> TestResult {
    let first = page(&[
        &entry("p/a.csv", "e", "1"),
        "<IsTruncated>true</IsTruncated><NextContinuationToken>t2</NextContinuationToken>",
    ]);
    let second = page(&[&entry("p/b.csv", "e", "1"), &entry("p/skip.exe", "e", "1")]);
    let (listing, calls) = walk(&|index| {
        if index == 0 {
            reply(STATUS_OK, &first)
        } else {
            reply(STATUS_OK, &second)
        }
    })?;
    let walked = listing?;
    assert_eq!(calls, TWO);
    assert_eq!(walked.objects.len(), TWO);
    assert_eq!(walked.skipped_key, 1);
    assert!(!walked.incomplete);
    Ok(())
}


#[test]
fn a_listing_still_truncated_after_the_page_cap_is_reported_incomplete() -> TestResult {
    let endless = page(&[
        &entry("p/a.csv", "e", "1"),
        "<IsTruncated>true</IsTruncated><NextContinuationToken>again</NextContinuationToken>",
    ]);
    let (listing, calls) = walk(&|_index| reply(STATUS_OK, &endless))?;
    assert_eq!(calls, MAX_LIST_PAGES);
    assert!(listing?.incomplete);
    Ok(())
}


#[test]
fn a_failing_page_fails_the_listing() -> TestResult {
    let (status, _) = walk(&|_index| reply(STATUS_ERROR, "<Error>marker</Error>"))?;
    assert!(matches!(status, Err(FetchError::Status(STATUS_ERROR))));
    let (transport, _) = walk(&|_index| Err(HttpFailure(HttpClass::Timeout)))?;
    assert!(matches!(transport, Err(FetchError::Transport(HttpClass::Timeout))));
    Ok(())
}


#[test]
fn an_oversized_or_non_utf8_page_is_refused_before_the_parse() -> TestResult {
    let huge = vec![b'x'; usize::try_from(MAX_LIST_BYTES)? + 1];
    let (too_large, _) = walk(&|_index| {
        Ok(HttpResponse {
            status: STATUS_OK,
            body: huge.clone(),
        })
    })?;
    assert!(matches!(too_large, Err(FetchError::ListTooLarge)));
    let (not_utf8, _) = walk(&|_index| {
        Ok(HttpResponse {
            status: STATUS_OK,
            body: NOT_UTF8.to_vec(),
        })
    })?;
    assert!(matches!(not_utf8, Err(FetchError::ListMalformed)));
    Ok(())
}


#[test]
fn list_page_and_get_body_use_the_injected_step() -> TestResult {
    let http = |request: &cloud_cost::fetch_model::HttpRequest| {
        assert_eq!(request.max_response, MAX_LIST_BYTES + 1);
        reply(STATUS_OK, &page(&[]))
    };
    let exec = |_sql: &str, _params: &[String]| Ok(Vec::new());
    let load = |_tenant: &str, _export: &cloud_cost::source::Export| Ok(cloud_cost::load::LoadOutcome::default());
    let limits = Limits::default();
    let env = env_of(&http, &exec, &load, &limits);
    let bucket = open_bucket(&source())?;
    assert!(list_page(&env, &source(), &bucket, &credentials(), None, None)?.objects.is_empty());
    assert!(get_body(&env, &source(), "https://s3.example.test/".to_owned(), MAX_LIST_BYTES + 1).is_ok());
    Ok(())
}


#[test]
fn the_key_count_is_enforced_in_the_walk_whatever_the_spelling() -> TestResult {
    let spellings = [
        "<Contents ><Key>p/a.csv</Key></Contents >",
        "<Contents\n><Key>p/a.csv</Key></Contents\n>",
        "<x:Contents><Key>p/a.csv</Key></x:Contents>",
        "<Contents/>",
        "<Contents />",
    ];
    spellings.iter().try_for_each(|spelling| {
        let over = spelling.repeat(MAX_KEYS_PER_PAGE + 1);
        assert!(
            matches!(parse_page(&page(&[&over]), PREFIX), Err(FetchError::ListTooManyKeys)),
            "{spelling}"
        );
        let exact = spelling.repeat(MAX_KEYS_PER_PAGE);
        assert!(parse_page(&page(&[&exact]), PREFIX).is_ok(), "{spelling}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    let mixed = format!("{}{}", "<Contents/>".repeat(MAX_KEYS_PER_PAGE), entry("p/a.csv", "e", "1"));
    assert!(matches!(parse_page(&page(&[&mixed]), PREFIX), Err(FetchError::ListTooManyKeys)));
    Ok(())
}


#[test]
fn an_etag_over_the_cap_or_outside_printable_ascii_skips_that_object_alone() -> TestResult {
    let long = "e".repeat(MAX_ETAG_BYTES);
    let longer = "e".repeat(MAX_ETAG_BYTES + 1);
    assert!(etag_ok(&long) && !etag_ok(&longer) && !etag_ok("a b") && !etag_ok("a\u{e9}") && etag_ok("\"abc\""));
    let text = page(&[
        &entry("p/a.csv", &longer, "1"),
        "<Contents><Key>p/c.csv</Key><ETag>a\u{e9}</ETag><Size>1</Size></Contents>",
        &entry("p/d.csv", "fine", "1"),
    ]);
    let parsed = parse_page(&text, PREFIX)?;
    assert_eq!(parsed.skipped, TWO);
    assert_eq!(parsed.objects.len(), 1);
    Ok(())
}


#[test]
fn the_last_key_of_a_page_is_the_resume_point_even_when_it_is_filtered() -> TestResult {
    let text = page(&[&entry("p/a.csv", "e", "1"), &entry("p/z.exe", "e", "1"), &entry("p/%0a.csv", "e", "1")]);
    assert_eq!(parse_page(&text, PREFIX)?.last_key.as_deref(), Some("p/z.exe"));
    let plain = format!("{HEAD}<Contents><Key>p/q.csv</Key><ETag>e</ETag><Size>1</Size></Contents>{TAIL}");
    assert_eq!(parse_page(&plain, PREFIX)?.last_key.as_deref(), Some("p/q.csv"));
    assert_eq!(parse_page(&page(&[]), PREFIX)?.last_key, None);
    let long = Pending {
        key: Some("a".repeat(MAX_KEY_BYTES + 1)),
        ..Pending::default()
    };
    assert_eq!(cursor_key(&[long], false), None);
    Ok(())
}


#[test]
fn a_listing_resumes_after_its_cursor_and_names_its_last_key_when_cut() -> TestResult {
    let endless = page(&[
        &entry("p/a.csv", "e", "1"),
        "<IsTruncated>true</IsTruncated><NextContinuationToken>again</NextContinuationToken>",
    ]);
    let ((listing, _), urls) = walk_from(&|_index| reply(STATUS_OK, &endless), Some("p/start.csv"))?;
    let cut = listing?;
    assert!(cut.incomplete);
    assert_eq!(cut.last_key.as_deref(), Some("p/a.csv"));
    let resumes: Vec<bool> = urls
        .iter()
        .map(|url| Url::parse(url).is_ok_and(|parsed| parsed.query_pairs().any(|(name, value)| name == "start-after" && value == "p/start.csv")))
        .collect();
    assert_eq!(resumes.first(), Some(&true));
    assert!(resumes.iter().skip(1).all(|found| !found));
    let blank = page(&["<IsTruncated>true</IsTruncated><NextContinuationToken>again</NextContinuationToken>"]);
    let ((kept, _), _) = walk_from(&|_index| reply(STATUS_OK, &blank), Some("p/start.csv"))?;
    assert_eq!(kept?.last_key.as_deref(), Some("p/start.csv"));
    Ok(())
}
