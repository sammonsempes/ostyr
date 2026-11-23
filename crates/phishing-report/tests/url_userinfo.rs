use cases::model::ObservableKind;
use phishing_report::limits::Limits;
use phishing_report::model::{Counts, ReporterPolicy, Triage};
use phishing_report::observables::observables;
use phishing_report::triage::{triage, triage_with};
use phishing_report::urls::{collect_indexed, index_from, split_region, Region, URL_RULE};


const PAD: usize = 2100;


const SPLIT: &str = "url_userinfo_split";


const UNREAD: &str = "url_host_unread";


const AMBIGUOUS: &str = "url_host_ambiguous";


const DECOYS: usize = 500;


const MANY: usize = 8000;


const FEW: usize = 100;


const SMALL_BOUND: usize = 4;


fn message(content_type: &str, body: &str, limits: &Limits) -> Result<Triage, Box<dyn std::error::Error>> {
    let raw = format!("From: p@evil.test\r\nContent-Type: {content_type}\r\n\r\n{body}\r\n");
    Ok(triage_with(
        raw.as_bytes(),
        &["mx.example.org".to_owned()],
        &ReporterPolicy::default(),
        limits,
    )?)
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


const FORMS: [(&str, &str, &str); 7] = [
    ("o_quote_userinfo", "text/html", "<a href='https://good.test\"@qu.evil.test/x'>x</a>"),
    ("o_quote_entity", "text/html", "<a href=\"https://good.test&quot;@qe.evil.test/x\">x</a>"),
    ("o_apos_userinfo", "text/html", "<a href=\"https://good.test'@ap.evil.test/x\">x</a>"),
    ("o_lt_userinfo", "text/html", "<a href='https://good.test<@lt.evil.test/x'>x</a>"),
    ("o_gt_userinfo", "text/html", "<a href='https://good.test>@gt.evil.test/x'>x</a>"),
    ("o_space_userinfo", "text/html", "<a href='https://good.test @sp.evil.test/x'>x</a>"),
    ("o_quote_text", "text/plain", "see https://good.test\"@tx.evil.test/x now"),
];


#[test]
fn each_of_the_seven_forms_lists_the_real_host_and_is_flagged_once() -> Result<(), Box<dyn std::error::Error>> {
    FORMS.iter().try_for_each(|(name, content_type, body)| {
        let record = message(content_type, body, &Limits::default())?;
        let hosts = domains(&record);
        let real = hosts.iter().filter(|host| host.ends_with(".evil.test")).count();
        assert_eq!(real, 1, "{name}: {hosts:?}");
        assert!(record.urls.iter().any(|hit| hit.url.starts_with("https://good.test")), "{name}");
        assert!(record.counts.url_userinfo_split > 0, "{name}");
        assert!(record.original_uncertain, "{name}");
        assert_eq!(reasons(&record, SPLIT), 1, "{name}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_seven_forms_in_one_message_name_the_reason_once() -> Result<(), Box<dyn std::error::Error>> {
    let body: String = FORMS
        .iter()
        .filter(|(_, kind, _)| *kind == "text/html")
        .map(|(_, _, html)| format!("{html}\r\n"))
        .collect();
    let record = message("text/html", &body, &Limits::default())?;
    assert_eq!(
        domains(&record).iter().filter(|host| host.ends_with(".evil.test")).count(),
        FORMS.len() - 1
    );
    assert_eq!(reasons(&record, SPLIT), 1);
    Ok(())
}


#[test]
fn a_form_with_padding_past_the_bound_is_flagged_unread() -> Result<(), Box<dyn std::error::Error>> {
    let pad = "a".repeat(PAD);
    let body = format!("https://good.test\"{pad}@pad.evil.test/x");
    let record = message("text/plain", &body, &Limits::default())?;
    assert!(!domains(&record).contains(&"pad.evil.test".to_owned()));
    assert!(record.counts.url_host_unread > 0);
    assert_eq!(reasons(&record, UNREAD), 1);
    Ok(())
}


#[test]
fn an_at_sign_in_a_query_after_a_quote_lists_no_wrong_host() -> Result<(), Box<dyn std::error::Error>> {
    let record = message(
        "text/plain",
        "https://good.test/p\"b@wrong.evil.test/ https://good.test\"?q=@wrong.evil.test",
        &Limits::default(),
    )?;
    assert!(!domains(&record).contains(&"wrong.evil.test".to_owned()));
    assert_eq!(record.counts.url_userinfo_split, 0);
    assert!(!record.original_uncertain);
    Ok(())
}


#[test]
fn a_data_url_and_a_url_at_the_end_of_the_text_are_not_split() -> Result<(), Box<dyn std::error::Error>> {
    let record = message("text/plain", "data:text,a\"@wrong.evil.test/ https://good.test", &Limits::default())?;
    assert_eq!(record.counts.url_userinfo_split, 0);
    assert!(!record.original_uncertain);
    Ok(())
}


#[test]
fn a_quote_followed_by_text_without_an_at_sign_is_not_split() -> Result<(), Box<dyn std::error::Error>> {
    let record = message("text/plain", "\"https://good.test\" and more", &Limits::default())?;
    assert_eq!(record.counts.url_userinfo_split, 0);
    assert_eq!(record.counts.url_host_ambiguous, 1);
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    Ok(())
}


#[test]
fn the_real_host_is_listed_after_many_long_decoys() -> Result<(), Box<dyn std::error::Error>> {
    let decoys: String = (0..DECOYS).map(|i| format!("https://d{i}.test/{} \r\n", "b".repeat(PAD))).collect();
    let body = format!("{decoys}https://good.test\"@real.evil.test/x");
    let record = message("text/plain", &body, &Limits::default())?;
    assert!(domains(&record).contains(&"real.evil.test".to_owned()));
    assert_eq!(reasons(&record, SPLIT), 1);
    Ok(())
}


#[test]
fn a_spent_window_budget_is_flagged_unread_whatever_follows() -> Result<(), Box<dyn std::error::Error>> {
    let run = |times: usize| {
        let text = "http:a\"\n".repeat(times);
        let mut counts = Counts::default();
        let mut index = index_from(&[], Vec::new());
        collect_indexed(&URL_RULE, &text, 0, &Limits::default(), Vec::new(), &mut index, &mut counts);
        counts.url_host_unread
    };
    assert_eq!(run(FEW), 0);
    let spent = run(MANY);
    assert!(spent > 0 && spent < MANY, "{spent}");
    Ok(())
}


#[test]
fn the_region_stops_at_the_first_terminator_or_is_open_or_whole() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(split_region("ab@c/d", SMALL_BOUND * SMALL_BOUND), Region::Closed("ab@c")));
    assert!(matches!(split_region("ab@c", SMALL_BOUND * SMALL_BOUND), Region::Closed("ab@c")));
    assert!(matches!(split_region("abcd@c/d", SMALL_BOUND), Region::Open));
    Ok(())
}


#[test]
fn a_long_url_with_an_ip_host_lists_the_ip_as_an_observable() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: PAD,
        ..Limits::default()
    };
    let body = format!("https://10.0.0.7/{} https://[::1]/{}", "a".repeat(PAD), "b".repeat(PAD));
    let record = message("text/plain", &body, &limits)?;
    assert_eq!(record.refused_hosts, ["10.0.0.7", "::1"]);
    assert_eq!(record.counts.url_host_unread, 0);
    let seen = observables(&record, &ReporterPolicy::default());
    assert!(seen.contains(&(ObservableKind::Ip, "10.0.0.7".to_owned())));
    assert!(seen.contains(&(ObservableKind::Ip, "::1".to_owned())));
    assert!(!seen.iter().any(|(kind, value)| *kind == ObservableKind::Domain && value.contains(':')));
    Ok(())
}


#[test]
fn a_refused_host_past_the_cap_makes_the_verdict_uncertain_by_name() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        urls: 1,
        url_bytes: PAD,
        ..Limits::default()
    };
    let body = format!("https://a.evil.test/{} https://b.evil.test/{}", "a".repeat(PAD), "b".repeat(PAD));
    let record = message("text/plain", &body, &limits)?;
    assert_eq!(record.refused_hosts, ["a.evil.test"]);
    assert_eq!(reasons(&record, "url_cap_reached"), 1);
    let plain = triage(b"From: p@evil.test\r\n\r\nhttp://ok.test/\r\n", &[], &ReporterPolicy::default())?;
    assert_eq!(reasons(&plain, "url_cap_reached"), 0);
    Ok(())
}


const NO_SLASH_FORMS: [(&str, &str, &str); 9] = [
    ("f1_quote", "text/plain", "see https:\"@zq.evil.test/x now"),
    ("f1_apos", "text/plain", "see https:'@zq.evil.test/x now"),
    ("f1_lt", "text/plain", "see https:<@zq.evil.test/x now"),
    ("f1_space", "text/plain", "see https: @zq.evil.test/x now"),
    ("f1_entity", "text/html", "<a href=\"https:&quot;@zq.evil.test/x\">x</a>"),
    ("f1_tab_entity", "text/html", "<a href=\"https:&#9;\"@zq.evil.test/x\">x</a>"),
    ("f1_http", "text/plain", "see http:\"@zq.evil.test/x now"),
    ("f1_ftp", "text/plain", "see ftp:\"@zq.evil.test/x now"),
    ("f1_no_path", "text/plain", "https:\"@zq.evil.test"),
];


#[test]
fn a_delimiter_right_after_the_scheme_colon_lists_the_real_host() -> Result<(), Box<dyn std::error::Error>> {
    NO_SLASH_FORMS.iter().try_for_each(|(name, content_type, body)| {
        let record = message(content_type, body, &Limits::default())?;
        assert!(domains(&record).contains(&"zq.evil.test".to_owned()), "{name}: {:?}", domains(&record));
        assert_eq!(reasons(&record, SPLIT), 1, "{name}");
        assert!(record.urls.iter().all(|hit| hit.url != "https://"), "{name}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_bare_scheme_is_never_listed_or_flagged_without_a_delimiter_trail() -> Result<(), Box<dyn std::error::Error>> {
    let record = message("text/plain", "the https: scheme\r\nand data: too\r\nand https://", &Limits::default())?;
    assert!(record.urls.is_empty(), "{:?}", record.urls);
    assert_eq!(record.counts.url_userinfo_split, 0);
    Ok(())
}


#[test]
fn the_region_ends_at_the_attribute_value() -> Result<(), Box<dyn std::error::Error>> {
    let record = message("text/html", "<a href='https://good.test\"@np.evil.test'>click</a>", &Limits::default())?;
    assert!(domains(&record).contains(&"np.evil.test".to_owned()), "{:?}", domains(&record));
    assert_eq!(reasons(&record, SPLIT), 1);
    Ok(())
}


#[test]
fn a_second_at_sign_in_the_region_lists_both_readings() -> Result<(), Box<dyn std::error::Error>> {
    let record = message(
        "text/html",
        "<a href='https://g.test\"x@y\"@real.evil.test'>a</a> <a href='https://g.test\"@h.evil.test' title=\"a@b\">b</a>",
        &Limits::default(),
    )?;
    let hosts = domains(&record);
    assert!(hosts.contains(&"real.evil.test".to_owned()), "{hosts:?}");
    assert!(hosts.contains(&"h.evil.test".to_owned()), "{hosts:?}");
    Ok(())
}


#[test]
fn a_quote_inside_the_host_lists_the_host_and_is_flagged() -> Result<(), Box<dyn std::error::Error>> {
    [
        "https://good.test\"x.evil.test/y",
        "https://good.test'x.evil.test/y",
        "<a href='https://good.test\"x.evil.test'>c</a>",
    ]
    .iter()
    .try_for_each(|body| {
        let record = message("text/html", body, &Limits::default())?;
        assert!(
            domains(&record).iter().any(|host| host.contains("x.evil.test")),
            "{body}: {:?}",
            domains(&record)
        );
        assert_eq!(reasons(&record, AMBIGUOUS), 1, "{body}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn ordinary_quoting_is_not_a_quote_inside_the_host() -> Result<(), Box<dyn std::error::Error>> {
    let body = "<a href=\"https://x.test\">x</a> <b>https://y.test<br/></b> https://z.test<i>q</i>\r\n\"https://a.test\",\"https://b.test\"\r\n'https://c.test'.";
    let record = message("text/html", body, &Limits::default())?;
    assert_eq!(record.counts.url_userinfo_split, 0);
    assert!(record.counts.url_host_ambiguous > 0);
    assert_eq!(reasons(&record, AMBIGUOUS), 1);
    Ok(())
}


#[test]
fn a_spent_budget_names_both_reasons() -> Result<(), Box<dyn std::error::Error>> {
    let body = "http:a\"\r\n".repeat(MANY);
    let record = message("text/plain", &body, &Limits::default())?;
    assert_eq!(reasons(&record, UNREAD), 1);
    assert_eq!(reasons(&record, SPLIT), 1);
    Ok(())
}
