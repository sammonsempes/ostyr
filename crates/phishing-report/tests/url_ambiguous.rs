use cases::model::ObservableKind;
use phishing_report::limits::Limits;
use phishing_report::model::{ReporterPolicy, Shapes, Triage};
use phishing_report::observables::observables;
use phishing_report::shapes::{
    address_follows, cid_reference, closes_attribute, edge, has_reference, head, vouch, window_after, window_before, Vouched,
};
use phishing_report::triage::triage_with;


const AMBIGUOUS: &str = "url_host_ambiguous";


const SPLIT: &str = "url_userinfo_split";


const FOLLOWERS: [&str; FOLLOWER_COUNT] = [
    "-", "_", ".", "%41", "*", "~", "!", "$", "=", "+", "&", "(", "{", "}", "`", ",", ";", "\"", "'", "é", "ａ", "a", "0", ")", "x",
];


const SMALL_BOUND: usize = 24;


const DEFAULT_BOUND: usize = 2048;


const REPEATS: usize = 600_000;


const REGION_BOUND: usize = 64;


const TIGHT_BOUND: usize = 8;


const SHORT_HEAD: usize = 4;


const CONTEXTS: usize = 3;


const QUOTES: usize = 2;


const FOLLOWER_COUNT: usize = 25;


fn run(content_type: &str, body: &str, limits: &Limits) -> Result<Triage, Box<dyn std::error::Error>> {
    let raw = format!("From: p@evil.test\r\nContent-Type: {content_type}\r\n\r\n{body}\r\n");
    Ok(triage_with(
        raw.as_bytes(),
        &["mx.example.org".to_owned()],
        &ReporterPolicy::default(),
        limits,
    )?)
}


fn message(content_type: &str, body: &str) -> Result<Triage, Box<dyn std::error::Error>> {
    run(content_type, body, &Limits::default())
}


fn domains(record: &Triage) -> Vec<String> {
    observables(record, &ReporterPolicy::default())
        .into_iter()
        .filter(|(kind, _)| *kind == ObservableKind::Domain)
        .map(|(_, value)| value)
        .collect()
}


fn reasons(record: &Triage, wanted: &str) -> usize {
    record.uncertain_reasons.iter().filter(|reason| reason.as_str() == wanted).count()
}


fn listed(record: &Triage) -> bool {
    domains(record).iter().any(|host| host.ends_with(".evil.test"))
}


fn contexts(quote: &str, follower: &str) -> Vec<(&'static str, String)> {
    let inner = format!("https://good.test{quote}{follower}x.evil.test/y");
    let other = if quote == "\"" { "'" } else { "\"" };
    let entity = if quote == "\"" { "&quot;" } else { "&#39;" };
    vec![
        ("text/plain", inner.clone()),
        ("text/html", format!("<a href={other}{inner}{other}>x</a>")),
        ("text/html", format!("<a href=\"https://good.test{entity}{follower}x.evil.test/y\">x</a>")),
    ]
}


#[test]
fn every_follower_after_a_quote_in_text_href_and_entity_is_listed_and_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let (flagged, found, total) = ["\"", "'"]
        .iter()
        .flat_map(|quote| FOLLOWERS.iter().flat_map(move |follower| contexts(quote, follower)))
        .try_fold(
            (0, 0, 0),
            |(flagged, found, total), (content_type, body)| -> Result<(usize, usize, usize), Box<dyn std::error::Error>> {
                let record = message(content_type, &body)?;
                let is_flagged = reasons(&record, AMBIGUOUS) == 1 && record.original_uncertain;
                assert!(is_flagged, "not flagged: {body}");
                assert!(listed(&record), "not listed: {body}: {:?}", domains(&record));
                Ok((flagged + usize::from(is_flagged), found + usize::from(listed(&record)), total + 1))
            },
        )?;
    assert_eq!((flagged, found), (total, total));
    assert_eq!(total, QUOTES * FOLLOWERS.len() * CONTEXTS);
    Ok(())
}


const ORDINARY: [(&str, &str, &str); 7] = [
    ("href_close", "text/html", "<a href=\"https://corp.test\">Go</a>"),
    ("href_single", "text/html", "<a href='https://corp.test'>Go</a>"),
    ("href_attribute", "text/html", "<a href=\"https://corp.test\" target=\"_blank\">Go</a>"),
    ("href_crlf", "text/html", "<a href=\"https://corp.test\"\r\n target=\"_blank\">Go</a>"),
    (
        "cid_logo",
        "text/html",
        "<p>https://corp.test <img src=\"cid:image001.png@01D0.EF12\"></p>",
    ),
    ("address", "text/plain", "https://corp.test | ceo@corp.test"),
    ("word", "text/plain", "Visit https://corp.test for details"),
];


#[test]
fn each_ordinary_form_is_not_flagged_and_still_lists_its_host() -> Result<(), Box<dyn std::error::Error>> {
    ORDINARY.iter().try_for_each(|(name, content_type, body)| {
        let record = message(content_type, body)?;
        assert_eq!(
            reasons(&record, AMBIGUOUS) + reasons(&record, SPLIT),
            0,
            "{name}: {:?}",
            record.uncertain_reasons
        );
        assert!(!record.original_uncertain, "{name}");
        assert!(domains(&record).iter().any(|host| host == "corp.test"), "{name}: {:?}", domains(&record));
        Ok(())
    })
}


#[test]
fn the_address_shape_over_two_lines_and_at_the_end_of_the_text_is_honoured() -> Result<(), Box<dyn std::error::Error>> {
    ["https://corp.test | ceo@corp.test\r\nnext line", "https://corp.test | ceo@corp.test next"]
        .iter()
        .try_for_each(|body| {
            let record = message("text/plain", body)?;
            assert!(!record.original_uncertain, "{body}");
            Ok(())
        })
}


const ATTACKS: [(&str, &str, &str, &str); 9] = [
    (
        "href_address",
        "text/html",
        "<a href=\"https://good.test | ceo@x.evil.test/\">x</a>",
        SPLIT,
    ),
    (
        "href_address_closed",
        "text/html",
        "<a href=\"https://good.test | ceo@x.evil.test \">x</a>",
        SPLIT,
    ),
    (
        "href_address_spaced",
        "text/html",
        "<a href=\" https://good.test | ceo@x.evil.test \">x</a>",
        SPLIT,
    ),
    (
        "cid_entity",
        "text/html",
        "<a href=\"https://good.test&quot; src=&quot;cid:a@x.evil.test/x\">x</a>",
        SPLIT,
    ),
    (
        "cid_unclosed",
        "text/html",
        "<p>https://good.test <img src=\"cid:a@x.evil.test/x\"></p>",
        SPLIT,
    ),
    ("double_quote", "text/plain", "https://good.test\"\"x.evil.test/", AMBIGUOUS),
    (
        "attribute_entity",
        "text/html",
        "<a href=\"https://good.test&quot; target=&quot;x@x.evil.test/\">x</a>",
        AMBIGUOUS,
    ),
    (
        "cid_entity_shape",
        "text/html",
        "<p>https://good.test <img src=&quot;cid:a@x.evil.test&quot;></p>",
        SPLIT,
    ),
    ("address_in_html", "text/html", "<p>https://good.test | ceo@x.evil.test </p>", SPLIT),
];


#[test]
fn every_attack_is_listed_and_flagged() -> Result<(), Box<dyn std::error::Error>> {
    ATTACKS.iter().try_for_each(|(name, content_type, body, reason)| {
        let record = message(content_type, body)?;
        assert!(reasons(&record, reason) >= 1, "{name}: {:?}", record.uncertain_reasons);
        assert!(
            domains(&record).iter().any(|host| host.contains("x.evil.test")),
            "{name}: {:?}",
            domains(&record)
        );
        Ok(())
    })
}


#[test]
fn the_entity_encoded_attribute_shape_is_flagged_and_the_literal_one_is_not() -> Result<(), Box<dyn std::error::Error>> {
    let literal = message("text/html", "<a href=\"https://corp.test\" target=\"_blank\">Go</a>")?;
    let encoded = message("text/html", "<a href=\"https://corp.test&quot; target=&quot;_blank\">Go</a>")?;
    assert_eq!(reasons(&literal, AMBIGUOUS), 0);
    assert_eq!(reasons(&encoded, AMBIGUOUS), 1);
    Ok(())
}


#[test]
fn a_shape_that_fails_on_the_stripped_copy_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    let record = message("text/plain", "a=\"https://corp.test\"\tx=\"1\"")?;
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    let kept = message("text/plain", "a=\"https://corp.test\" x=\"1\"")?;
    assert_eq!(reasons(&kept, AMBIGUOUS), 0);
    Ok(())
}


#[test]
fn a_window_with_no_region_end_in_the_raw_bound_is_not_vouched() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: SMALL_BOUND,
        ..Limits::default()
    };
    let body = "https://corp.test | ceoceoceoceoceoceo@corp.test\nx";
    let record = run("text/plain", body, &limits)?;
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    let short = run("text/plain", "https://corp.test | ceo@corp.test\nx", &limits)?;
    assert_eq!(reasons(&short, SPLIT), 0);
    Ok(())
}


#[test]
fn a_region_with_no_end_in_the_bound_names_both_reasons() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: SMALL_BOUND,
        ..Limits::default()
    };
    let record = run("text/plain", "https://corp.test and more words in a long line of text", &limits)?;
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    assert_eq!(reasons(&record, "url_host_unread"), 1);
    Ok(())
}


#[test]
fn a_spent_budget_names_the_ambiguity_too() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: DEFAULT_BOUND,
        ..Limits::default()
    };
    let body = "http:a\" ".repeat(REPEATS);
    let record = run("text/plain", &body, &limits)?;
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    Ok(())
}


#[test]
fn a_reference_is_an_ampersand_followed_by_a_hash_or_a_letter() -> Result<(), Box<dyn std::error::Error>> {
    assert!(has_reference("a &amp; b"));
    assert!(has_reference("&#39;"));
    assert!(!has_reference("a & b &1 &"));
    assert!(!has_reference("none"));
    Ok(())
}


#[test]
fn edge_and_head_drop_line_noise_only_when_asked() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(edge("x=\t\"", REGION_BOUND, false), "\t\"");
    assert_eq!(edge("x=\t\"", REGION_BOUND, true), "=\"");
    assert_eq!(head("a\tb\nc", SHORT_HEAD, false), "a\tb\n");
    assert_eq!(head("a\tb\nc", SHORT_HEAD, true), "ab");
    Ok(())
}


#[test]
fn closes_attribute_needs_an_opening_the_same_quote_and_an_end() -> Result<(), Box<dyn std::error::Error>> {
    assert!(closes_attribute("x=\"", "\">y"));
    assert!(closes_attribute("x='", "' target=\"a\""));
    assert!(closes_attribute("x=\"", "\"\r\n\tdata-x=1"));
    assert!(!closes_attribute("x ", "\">y"));
    assert!(!closes_attribute("x=\"", "'>y"));
    assert!(!closes_attribute("x=\"", "\"y"));
    assert!(!closes_attribute("x=\"", "\" y"));
    assert!(!closes_attribute("x=\"", "\" 1=2"));
    assert!(!closes_attribute("x=\"", "\" y z=1"));
    assert!(!closes_attribute("x=\"", "\""));
    Ok(())
}


#[test]
fn cid_reference_needs_one_at_sign_and_its_own_closing_quote() -> Result<(), Box<dyn std::error::Error>> {
    assert!(cid_reference(" <img src=\"cid:a.b-c_d@01D0.EF\">"));
    assert!(cid_reference(" <img src='cid:a@b'>"));
    assert!(!cid_reference(" <img src=\"cid:a@b'>"));
    assert!(!cid_reference(" <img src=\"cid:a@b\"> @x"));
    assert!(!cid_reference(" <img src=\"cid:a@evil.test"));
    assert!(!cid_reference(" <img src=\"cid:@b\">"));
    assert!(!cid_reference(" <img src=\"cid:a@\">"));
    assert!(!cid_reference(" <img src=\"cid:a b@c\">"));
    assert!(!cid_reference(" <img src=\"x:a@b\">"));
    Ok(())
}


#[test]
fn address_follows_needs_the_separator_one_address_and_a_clean_end() -> Result<(), Box<dyn std::error::Error>> {
    assert!(address_follows(" | ceo+x@corp.test", None));
    assert!(address_follows(" | ceo@corp.test", Some('\n')));
    assert!(address_follows(" | ceo@corp.test next", Some('/')));
    assert!(!address_follows(" | ceo@corp.test", Some('/')));
    assert!(!address_follows(" | ceo@corp.test", Some('?')));
    assert!(!address_follows(" | ceo@corp.test\"", None));
    assert!(!address_follows(" | ceo@corp.test x@y", None));
    assert!(!address_follows(" | ceo@a@b", None));
    assert!(!address_follows(" | @corp.test", None));
    assert!(!address_follows(" | ceo@ x", None));
    assert!(!address_follows(" |ceo@corp.test", None));
    assert!(!address_follows(" | ceo", None));
    Ok(())
}


#[test]
fn vouch_is_empty_when_no_shape_holds_and_the_region_is_open() -> Result<(), Box<dyn std::error::Error>> {
    let none = Vouched::default();
    assert_eq!(vouch(Shapes::Plain, "x", ", y", REGION_BOUND), none);
    let open = vouch(Shapes::Plain, "x", &" | ceo@corp.test and long long text".repeat(SHORT_HEAD), TIGHT_BOUND);
    assert_eq!(open, none);
    assert!(vouch(Shapes::Plain, "x", " | ceo@corp.test", REGION_BOUND).userinfo);
    assert!(!vouch(Shapes::Markup, "x", " | ceo@corp.test", REGION_BOUND).userinfo);
    assert!(!vouch(Shapes::Plain, "=\"", " | ceo@corp.test", REGION_BOUND).userinfo);
    assert!(vouch(Shapes::Markup, "x", " src=\"cid:a@b\"", REGION_BOUND).userinfo);
    assert!(!vouch(Shapes::Markup, "x", " src=\"cid:a@b\"", REGION_BOUND).ambiguity);
    assert_eq!(
        vouch(Shapes::Markup, "=\"", "\">", REGION_BOUND),
        Vouched {
            ambiguity: true,
            userinfo: true
        }
    );
    Ok(())
}


#[test]
fn a_vouched_shape_still_lists_the_host_after_the_at_sign() -> Result<(), Box<dyn std::error::Error>> {
    [
        ("text/html", "<p>https://good.test <img src=\"cid:a@x.evil.test\"></p>"),
        ("text/plain", "https://good.test | ceo@x.evil.test"),
        ("text/html", "<a href=\"https://good.test\" title=\"mail @x.evil.test\">x</a>"),
    ]
    .iter()
    .try_for_each(|(content_type, body)| {
        let record = message(content_type, body)?;
        assert!(!record.original_uncertain, "{body}");
        assert!(
            domains(&record).iter().any(|host| host == "x.evil.test"),
            "{body}: {:?}",
            domains(&record)
        );
        Ok(())
    })
}


#[test]
fn head_and_edge_read_at_most_the_bound_in_raw_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let noise = "\t\n".repeat(REPEATS);
    let tail = format!("{noise}abc");
    let before = format!("abc{noise}");
    assert_eq!(head(&tail, REGION_BOUND, true), "");
    assert_eq!(head(&tail, REGION_BOUND, false).len(), REGION_BOUND);
    assert_eq!(edge(&before, REGION_BOUND, true), "");
    assert_eq!(window_after(&tail, REGION_BOUND).len(), REGION_BOUND);
    assert_eq!(window_before(&before, REGION_BOUND).len(), REGION_BOUND);
    assert_eq!(window_after("aé", TWO_BYTES), "a");
    assert_eq!(window_before("éa", TWO_BYTES), "a");
    assert_eq!(window_after("ab", REGION_BOUND), "ab");
    assert_eq!(window_before("ab", REGION_BOUND), "ab");
    Ok(())
}


#[test]
fn the_attack_shape_with_line_noise_after_each_match_is_flagged_within_the_bound() -> Result<(), Box<dyn std::error::Error>> {
    let noise = "\t\n".repeat(REPEATS);
    let record = message("text/plain", &format!("ftp:\"{noise}"))?;
    assert!(record.original_uncertain, "{:?}", record.uncertain_reasons);
    Ok(())
}


#[test]
fn only_text_plain_exactly_is_plain_and_every_other_text_subtype_is_markup() -> Result<(), Box<dyn std::error::Error>> {
    let body = "<a href=\"https://good.test&quot;x.evil.test/\">x</a>";
    ["text/x-amp-html", "text/enriched", "text/html"].iter().try_for_each(|kind| {
        let record = message(kind, body)?;
        assert_eq!(reasons(&record, AMBIGUOUS), 1, "{kind}: {:?}", record.uncertain_reasons);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let plain = message("TEXT/Plain", "Visit https://corp.test | ceo@corp.test")?;
    assert_eq!(reasons(&plain, AMBIGUOUS) + reasons(&plain, SPLIT), 0);
    let bare = message("text", "https://corp.test | ceo@corp.test")?;
    assert!(domains(&bare).iter().any(|host| host == "corp.test"));
    Ok(())
}


const TWO_BYTES: usize = 2;
