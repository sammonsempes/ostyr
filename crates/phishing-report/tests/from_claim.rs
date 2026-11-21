use mail_parser::{Header, Message, MessageParser};
use phishing_report::claim::{claim_scan, domain_set};
use phishing_report::error::TriageError;
#[cfg(unix)]
use phishing_report::isolate::{triage_isolated, Isolation, PRLIMIT_PROGRAM};
#[cfg(unix)]
use phishing_report::limits::Limits;
use phishing_report::limits::MAX_FROM_ADDRESSES;
use phishing_report::model::{Counts, ReporterPolicy, Triage};
use phishing_report::triage::{claim_from_raw, triage};
use std::collections::HashSet;
#[cfg(unix)]
use std::path::PathBuf;


const PASS_CORP: &str = "Authentication-Results: mx.corp.test; dmarc=pass header.from=corp.test";


const FORWARD_HEADERS: [&str; 2] = [PASS_CORP, "From: employee@corp.test"];


const OVER_HEADER: usize = 17 * 1024;


const TWO_READINGS: usize = 2;


const LONG_LOCAL: usize = 400;


const ONE_MEGABYTE: usize = 1024 * 1024;


const POLICY_DOMAINS: usize = 1024;


const ENTRIES_OVER_CAP: usize = MAX_FROM_ADDRESSES + 1;


const BOMB_PAIRS: usize = 100_000;


const OVER_RUN: usize = 300;


const WRAPPERS: usize = 2;


fn policy() -> ReporterPolicy {
    ReporterPolicy {
        internal_domains: vec!["corp.test".to_owned()],
    }
}


fn ids() -> Vec<String> {
    vec!["mx.corp.test".to_owned()]
}


fn run_bytes(raw: &[u8]) -> Result<Triage, TriageError> {
    triage(raw, &ids(), &policy())
}


fn run(text: &str) -> Result<Triage, TriageError> {
    run_bytes(text.as_bytes())
}


fn mail(headers: &[&str], body: &str) -> String {
    format!("{}\r\n\r\n{body}", headers.join("\r\n"))
}


fn from_only(from: &str) -> String {
    mail(&[from, "Subject: s"], "x")
}


fn forward_with(part: &str) -> String {
    let mut all = FORWARD_HEADERS.to_vec();
    all.push("MIME-Version: 1.0");
    all.push("Content-Type: multipart/mixed; boundary=\"OUT\"");
    mail(
        &all,
        &format!("--OUT\r\nContent-Type: text/plain\r\n\r\nfyi\r\n--OUT\r\n{part}\r\n--OUT--\r\n"),
    )
}


fn as_rfc822(message: &str) -> String {
    format!("Content-Type: message/rfc822\r\n\r\n{message}")
}


fn as_eml(message: &str) -> String {
    format!("Content-Type: application/octet-stream; name=\"a.eml\"\r\nContent-Disposition: attachment; filename=\"a.eml\"\r\n\r\n{message}")
}


fn padded(address: &str) -> String {
    format!("From: {address} ({})", "p".repeat(OVER_HEADER))
}


fn has_reason(record: &Triage, reason: &str) -> bool {
    record.uncertain_reasons.iter().any(|found| found == reason)
}


fn set_of(domains: &[&str]) -> HashSet<String> {
    domains.iter().map(|domain| (*domain).to_owned()).collect()
}


fn claims(raw: &str) -> bool {
    claim_scan(raw.as_bytes(), &set_of(&["corp.test"])).claimed
}


#[test]
fn a_from_whose_addresses_are_all_refused_is_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    let baseline = run(&from_only("From: a@evil.test"))?;
    assert!(!baseline.original_uncertain);
    let long_local = format!("From: <{}@evil.test>", "a".repeat(LONG_LOCAL));
    let forms = [
        "From: <a\u{1b}b@evil.test>".to_owned(),
        "From: <a\u{200b}b@evil.test>".to_owned(),
        "From: <a\u{202e}b@evil.test>".to_owned(),
        long_local,
    ];
    forms.iter().try_for_each(|form| {
        let record = run(&from_only(form))?;
        assert_eq!(record.original_level, Some(0), "{form}");
        assert!(has_reason(&record, "from_unparsed"), "{form}");
        assert!(record.original_uncertain, "{form}");
        assert!(record.senders.is_empty(), "{form}");
        Ok::<(), TriageError>(())
    })?;
    Ok(())
}


#[test]
fn an_entry_without_an_address_makes_the_from_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    let list = run(&from_only("From: \"x\" <a@evil.test>, \"y\""))?;
    assert_eq!(list.senders, ["a@evil.test"]);
    assert!(has_reason(&list, "from_unparsed"));
    let group = run(&from_only("From: Team: a@evil.test, \"y\";"))?;
    assert!(has_reason(&group, "from_unparsed"));
    let empty_group = run(&from_only("From: Team: ;"))?;
    assert!(has_reason(&empty_group, "from_unparsed"));
    Ok(())
}


#[test]
fn more_than_the_cap_of_entries_is_unparsed_and_the_cap_itself_is_not() -> Result<(), Box<dyn std::error::Error>> {
    let list = |count: usize| (0..count).map(|i| format!("u{i}@evil.test")).collect::<Vec<_>>().join(", ");
    let at_cap = run(&from_only(&format!("From: {}", list(MAX_FROM_ADDRESSES))))?;
    assert!(!at_cap.original_uncertain);
    let over = run(&from_only(&format!("From: {}", list(ENTRIES_OVER_CAP))))?;
    assert!(has_reason(&over, "from_unparsed"));
    assert_eq!(over.senders.len(), MAX_FROM_ADDRESSES);
    Ok(())
}


#[test]
fn an_oversized_from_naming_an_internal_domain_is_claimed() -> Result<(), Box<dyn std::error::Error>> {
    let comment = run(&from_only(&padded("ceo@corp.test")))?;
    assert!(comment.internal_claimed);
    assert_eq!(comment.counts.internal_claimed, 1);
    assert!(has_reason(&comment, "internal_unauthenticated"));
    assert!(has_reason(&comment, "from_unparsed"));
    assert!(comment.counts.headers_skipped >= 1);
    let every = run(&from_only(&padded("ceo@corp.test (pad@evil.test)")))?;
    assert!(every.internal_claimed);
    let last_is_internal = run(&from_only(&padded("pad@evil.test (ceo@corp.test)")))?;
    assert!(last_is_internal.internal_claimed);
    let other = run(&from_only(&padded("ceo@evil.test")))?;
    assert!(!other.internal_claimed);
    assert!(has_reason(&other, "from_unparsed"));
    assert_eq!(other.uncertain_reasons, ["from_unparsed"]);
    Ok(())
}


#[test]
fn an_oversized_from_with_an_invalid_byte_in_its_comment_is_still_scanned() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = b"From: ceo@corp.test (\xff".to_vec();
    raw.extend(std::iter::repeat_n(b'p', OVER_HEADER));
    raw.extend(b")\r\nSubject: s\r\n\r\nx");
    let record = run_bytes(&raw)?;
    assert!(record.internal_claimed);
    assert!(has_reason(&record, "from_unparsed"));
    Ok(())
}


#[test]
fn a_domain_with_a_space_or_a_comment_is_still_claimed() -> Result<(), Box<dyn std::error::Error>> {
    [
        "From: ceo@ corp.test",
        "From: ceo@(c)corp.test",
        "From: ceo@[corp.test]",
        "From: a@evil.test, b@CORP.TEST.",
    ]
    .iter()
    .try_for_each(|form| {
        let record = run(&from_only(form))?;
        assert!(record.internal_claimed, "{form}");
        assert!(has_reason(&record, "internal_unauthenticated"), "{form}");
        Ok::<(), TriageError>(())
    })?;
    let spaced = run(&from_only("From: ceo@ corp.test"))?;
    assert!(has_reason(&spaced, "from_unparsed"));
    Ok(())
}


#[test]
fn the_claim_scan_reads_every_at_sign_a_comment_a_bracket_and_a_dot() -> Result<(), Box<dyn std::error::Error>> {
    assert!(claims("ceo@corp.test (pad@evil.test)"));
    assert!(claims("x@evil.test (ceo@corp.test)"));
    assert!(claims("ceo@evil.test \"@corp.test\""));
    assert!(claims("ceo@(a)(b)corp.test"));
    assert!(claims("ceo@((a)b)corp.test"));
    assert!(claims("ceo@(\\)x)corp.test"));
    assert!(claims("ceo@(c)[corp.test]"));
    assert!(claims("ceo@\r\n corp.test"));
    assert!(claims("ceo@ \t(c) [corp.test]"));
    assert!(claims("ceo@c\r\n orp.\ttest"));
    assert!(claims("ceo@CORP.test."));
    assert!(!claims("ceo@evil.test"));
    assert!(!claims("ceo@corp-x.test"));
    assert!(claim_scan(b"ceo@corp-x.test", &set_of(&["corp-x.test"])).claimed);
    assert!(!claims("ceo@corp.test.evil.test"));
    assert!(!claims("ceo@[(x)corp.test"));
    assert!(!claims("ceo@[[corp.test]"));
    assert!(!claims("ceo@corp(x).test"));
    assert!(!claims("ceo=40corp.test"));
    assert!(!claims("ceo@"));
    assert!(!claims("ceo@(corp.test"));
    assert!(!claims("ceo@(c)\\(corp.test)x"));
    assert!(!claims(""));
    Ok(())
}


#[test]
fn whitespace_ends_a_domain_run_instead_of_gluing_words_to_it() -> Result<(), Box<dyn std::error::Error>> {
    assert!(claims("ceo@corp.test Chief Executive"));
    assert!(claims("ceo@corp.test\r\n Chief"));
    assert!(!claims("ceo@corp.testChief"));
    assert!(!claims("ceo@corp.test.evil.test"));
    ["(", ")", "<", ">", ",", ";", "\""].iter().try_for_each(|end| {
        assert!(claims(&format!("ceo@corp.test{end}x")), "{end}");
        assert!(!claims(&format!("ceo@corp{end}.test")), "{end}");
        Ok::<(), TriageError>(())
    })?;
    let small = run(&from_only("From: ceo@corp.test Chief Executive"))?;
    assert!(small.internal_claimed);
    assert!(has_reason(&small, "internal_unauthenticated"));
    let folded = format!("From: ceo@corp.test{}", "\r\n x".repeat(OVER_HEADER));
    let big = run(&from_only(&folded))?;
    assert!(big.internal_claimed);
    assert!(has_reason(&big, "from_unparsed"));
    let dashed = run(&from_only(&padded("ceo@corp.test-evil")))?;
    assert!(!dashed.internal_claimed);
    Ok(())
}


#[test]
fn whitespace_inside_a_domain_is_read_both_ways() -> Result<(), Box<dyn std::error::Error>> {
    [
        "<ceo@corp. test>",
        "<ceo@corp .test>",
        "<ceo @ corp. test>",
        "<ceo@corp.\ttest>",
        "<ceo@CORP. TEST>",
        "<ceo@corp\t.test>",
        "ceo@corp.te st",
        "<ceo@corp.\r\n test>",
    ]
    .iter()
    .try_for_each(|form| {
        assert!(claims(form), "{form}");
        let record = run(&from_only(&format!("From: {form}")))?;
        assert!(record.internal_claimed, "{form}");
        assert!(has_reason(&record, "internal_unauthenticated"), "{form}");
        Ok::<(), TriageError>(())
    })?;
    assert!(!claims("<ceo@corp. tes>"));
    assert!(!claims("<ceo@corp .evil>"));
    let both = claim_scan(b"ceo@corp. test", &set_of(&["corp.test"]));
    assert_eq!(both.lookups, TWO_READINGS);
    Ok(())
}


#[test]
fn a_first_reading_hit_skips_the_second_and_a_miss_runs_both() -> Result<(), Box<dyn std::error::Error>> {
    let direct = claim_scan(b"a@corp.test", &set_of(&["corp.test"]));
    assert_eq!(direct.lookups, 1);
    let miss = claim_scan(b"a@evil.test", &set_of(&["corp.test"]));
    assert!(!miss.claimed);
    assert_eq!(miss.lookups, TWO_READINGS);
    Ok(())
}


#[test]
fn a_group_with_no_first_address_leaves_no_sender_and_is_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    ["From: Corp CEO:;, a@evil.test", "From: undisclosed:;, a@evil.test"]
        .iter()
        .try_for_each(|form| {
            let record = run(&from_only(form))?;
            assert!(record.sender.is_none(), "{form}");
            assert!(has_reason(&record, "from_unparsed"), "{form}");
            assert!(record.original_uncertain, "{form}");
            Ok::<(), TriageError>(())
        })?;
    let fine = run(&from_only("From: a@evil.test"))?;
    assert!(fine.sender.is_some());
    assert!(!has_reason(&fine, "from_unparsed"));
    Ok(())
}


#[test]
fn display_names_naming_an_internal_domain_are_claimed() -> Result<(), Box<dyn std::error::Error>> {
    ["From: \"ceo@corp.test x\" <a@evil.test>", "From: a@evil.test (ceo@corp.test x)"]
        .iter()
        .try_for_each(|form| {
            let record = run(&from_only(form))?;
            assert!(record.internal_claimed, "{form}");
            assert!(has_reason(&record, "internal_unauthenticated"), "{form}");
            Ok::<(), TriageError>(())
        })?;
    Ok(())
}


#[test]
fn an_original_with_no_from_header_is_unparsed() -> Result<(), Box<dyn std::error::Error>> {
    let sender_only = run(&mail(&["Sender: ceo@corp.test", "Subject: s"], "x"))?;
    assert_eq!(sender_only.original_level, Some(0));
    assert!(has_reason(&sender_only, "from_unparsed"));
    assert!(sender_only.original_uncertain);
    let renamed = run(&mail(&["X-Mailbox-Line: ceo@corp.test", "Subject: s"], "x"))?;
    assert!(has_reason(&renamed, "from_unparsed"));
    let none = run(&mail(&["Subject: s"], "x"))?;
    assert!(has_reason(&none, "from_unparsed"));
    Ok(())
}


#[test]
fn a_run_longer_than_any_domain_is_cut_and_never_matches() -> Result<(), Box<dyn std::error::Error>> {
    let long = format!("a@{}", "a".repeat(OVER_RUN));
    assert!(!claims(&long));
    let policy = set_of(&[&"a".repeat(OVER_RUN)]);
    assert!(!claim_scan(long.as_bytes(), &policy).claimed);
    Ok(())
}


#[test]
fn a_hash_set_gives_one_lookup_per_at_sign_and_never_a_walk_of_the_list() -> Result<(), Box<dyn std::error::Error>> {
    let raw = "@".repeat(ONE_MEGABYTE);
    let domains: Vec<String> = (0..POLICY_DOMAINS).map(|i| format!("d{i}.test")).collect();
    let set = domain_set(&ReporterPolicy { internal_domains: domains });
    let scanned = claim_scan(raw.as_bytes(), &set);
    assert_eq!(scanned.lookups, ONE_MEGABYTE * TWO_READINGS);
    assert!(!scanned.claimed);
    assert!(!scanned.exhausted);
    assert_eq!(domain_set(&policy()), set_of(&["corp.test"]));
    let upper = domain_set(&ReporterPolicy {
        internal_domains: vec!["CORP.Test".to_owned()],
    });
    assert_eq!(upper, set_of(&["corp.test"]));
    Ok(())
}


#[test]
fn an_oversized_from_of_many_at_signs_under_a_large_policy_gives_a_result() -> Result<(), Box<dyn std::error::Error>> {
    let domains: Vec<String> = (0..POLICY_DOMAINS).map(|i| format!("d{i}.test")).collect();
    let large = ReporterPolicy { internal_domains: domains };
    let raw = format!("From: {}\r\nSubject: s\r\n\r\nx", "@".repeat(ONE_MEGABYTE));
    let record = triage(raw.as_bytes(), &ids(), &large)?;
    assert!(!record.internal_claimed);
    assert!(has_reason(&record, "from_unparsed"));
    assert_eq!(record.counts.claim_exhausted, 0);
    Ok(())
}


#[cfg(unix)]
#[test]
fn the_isolated_child_answers_the_one_megabyte_of_at_signs() -> Result<(), Box<dyn std::error::Error>> {
    let domains: Vec<String> = (0..POLICY_DOMAINS).map(|i| format!("d{i}.test")).collect();
    let large = ReporterPolicy { internal_domains: domains };
    let raw = format!("From: {}\r\nSubject: s\r\n\r\nx", "@".repeat(ONE_MEGABYTE));
    let isolation = Isolation {
        prlimit: PathBuf::from(PRLIMIT_PROGRAM),
        program: PathBuf::from(env!("CARGO_BIN_EXE_phish_triage")),
    };
    let record = triage_isolated(raw.as_bytes(), &ids(), &large, &Limits::default(), &isolation)?;
    assert!(has_reason(&record, "from_unparsed"));
    assert!(!record.internal_claimed);
    Ok(())
}


#[test]
fn a_comment_bomb_spends_the_budget_and_claims_loudly() -> Result<(), Box<dyn std::error::Error>> {
    let bomb = "@(".repeat(BOMB_PAIRS);
    let scanned = claim_scan(bomb.as_bytes(), &set_of(&["corp.test"]));
    assert!(scanned.exhausted);
    assert!(scanned.claimed);
    let record = run(&format!("From: {bomb}\r\nSubject: s\r\n\r\nx"))?;
    assert!(record.internal_claimed);
    assert_eq!(record.counts.claim_exhausted, 1);
    assert!(has_reason(&record, "from_unparsed"));
    Ok(())
}


#[test]
fn a_nested_original_is_read_raw_at_level_one_through_a_message_and_an_eml() -> Result<(), Box<dyn std::error::Error>> {
    let wrappers: [fn(&str) -> String; WRAPPERS] = [as_rfc822, as_eml];
    wrappers.iter().try_for_each(|wrap| {
        let big = run(&forward_with(&wrap(&from_only(&padded("ceo@corp.test")))))?;
        assert_eq!(big.original_level, Some(1));
        assert!(big.internal_claimed);
        assert_eq!(big.counts.claim_unreadable, 0);
        assert!(has_reason(&big, "attached_claim"));
        assert!(has_reason(&big, "from_unparsed"));
        let small = run(&forward_with(&wrap(&from_only("From: ceo@corp.test (x)"))))?;
        assert!(small.internal_claimed);
        let plain = run(&forward_with(&wrap(&from_only("From: a@evil.test"))))?;
        assert_eq!(plain.original_level, Some(1));
        assert!(!plain.internal_claimed);
        assert_eq!(plain.counts.claim_unreadable, 0);
        assert_eq!(plain.uncertain_reasons, ["attached_claim"]);
        let other = run(&forward_with(&wrap(&from_only(&padded("ceo@evil.test")))))?;
        assert!(!other.internal_claimed);
        assert_eq!(other.counts.claim_unreadable, 0);
        Ok::<(), TriageError>(())
    })?;
    Ok(())
}


fn unreadable<'a>(_message: &'a Message<'_>, _header: &Header<'_>) -> Option<&'a [u8]> {
    None
}


fn readable<'a>(message: &'a Message<'_>, header: &Header<'_>) -> Option<&'a [u8]> {
    message.raw_message().get(header.offset_start as usize..header.offset_end as usize)
}


#[test]
fn a_from_value_that_cannot_be_read_raw_claims_and_is_counted() -> Result<(), Box<dyn std::error::Error>> {
    let text = mail(&["From: a@evil.test", "From: ceo@corp.test", "Subject: s"], "x");
    let message = MessageParser::default().parse(text.as_bytes()).ok_or("no parse")?;
    let set = set_of(&["corp.test"]);
    let mut counts = Counts::default();
    assert_eq!(claim_from_raw(&message, message.headers(), &set, unreadable, &mut counts), (true, true));
    assert_eq!(counts.claim_unreadable, WRAPPERS);
    let mut read_counts = Counts::default();
    assert_eq!(
        claim_from_raw(&message, message.headers(), &set, readable, &mut read_counts),
        (true, false)
    );
    assert_eq!(read_counts.claim_unreadable, 0);
    let none = ReporterPolicy::default();
    let nothing = domain_set(&none);
    assert_eq!(claim_from_raw(&message, &[], &nothing, readable, &mut read_counts), (false, false));
    Ok(())
}
