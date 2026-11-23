use cases::model::ObservableKind;
use phishing_report::limits::Limits;
use phishing_report::model::{Counts, ReporterPolicy, Triage, UrlHit};
use phishing_report::observables::observables;
use phishing_report::urls::{collect, collect_indexed, html_text, index_from, URL_RULE};


const KEPT: usize = 40;


const PAD: usize = 200;


const REPEATS: usize = 3;


fn links(found: &[UrlHit]) -> Vec<&str> {
    found.iter().map(|hit| hit.url.as_str()).collect()
}


#[test]
fn every_match_costs_one_lookup_of_its_own_length_whatever_the_number_kept() -> Result<(), Box<dyn std::error::Error>> {
    let pad = "a".repeat(PAD);
    let one: String = (0..KEPT).map(|i| format!("http://h.test/{pad}{i:04} ")).collect();
    let text = one.repeat(REPEATS);
    let mut counts = Counts::default();
    let mut index = index_from(&[], Vec::new());
    let found = collect_indexed(&URL_RULE, &text, 0, &Limits::default(), Vec::new(), &mut index, &mut counts);
    assert_eq!(found.len(), KEPT);
    assert_eq!(index.probes, KEPT * REPEATS);
    let url_bytes = "http://h.test/".len() + PAD + "0000".len();
    assert_eq!(index.probed_bytes, KEPT * REPEATS * url_bytes);
    Ok(())
}


#[test]
fn a_url_refused_for_a_control_character_in_its_path_still_lists_its_host() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let text = html_text(
        "<a href='https://ph&#9;ish.evil.test/a&#27;b'>x</a> <a href='https://ph&#9;ish.evil.test/c&#27;d'>",
        &mut counts,
    );
    let mut index = index_from(&[], Vec::new());
    let found = collect_indexed(&URL_RULE, &text, 0, &Limits::default(), Vec::new(), &mut index, &mut counts);
    assert!(!links(&found).contains(&"https://phish.evil.test/a%1Bb"));
    assert!(counts.urls_refused > 0);
    assert_eq!(index.hosts, ["phish.evil.test"]);
    assert_eq!(counts.url_refused_host_kept, 1);
    let record = Triage {
        refused_hosts: index.hosts,
        ..Triage::default()
    };
    let seen = observables(&record, &ReporterPolicy::default());
    assert_eq!(seen, [(ObservableKind::Domain, "phish.evil.test".to_owned())]);
    Ok(())
}


#[test]
fn a_refusal_with_no_readable_host_or_a_cut_host_lists_no_host() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: PAD,
        ..Limits::default()
    };
    let text = format!("https://ev\u{1b}il.test/x https://{} https://[bad\u{1b} http://ok.test/", "a".repeat(PAD));
    let mut counts = Counts::default();
    let mut index = index_from(&[], Vec::new());
    collect_indexed(&URL_RULE, &text, 0, &limits, Vec::new(), &mut index, &mut counts);
    assert!(index.hosts.is_empty());
    assert_eq!(counts.url_refused_host_kept, 0);
    Ok(())
}


#[test]
fn a_url_refused_for_length_still_lists_a_host_read_inside_the_bound() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        url_bytes: PAD,
        ..Limits::default()
    };
    let text = format!("https://long.test/{} https://other.test/?{}", "a".repeat(PAD), "b".repeat(PAD));
    let mut counts = Counts::default();
    let mut index = index_from(&[], Vec::new());
    let found = collect_indexed(&URL_RULE, &text, 0, &limits, Vec::new(), &mut index, &mut counts);
    assert!(found.is_empty());
    assert_eq!(index.hosts, ["long.test", "other.test"]);
    assert_eq!(counts.url_refused_host_kept, index.hosts.len());
    Ok(())
}


#[test]
fn refused_hosts_are_capped_and_the_cap_is_named() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        urls: 1,
        ..Limits::default()
    };
    let text = "https://a.test/\u{1b} https://b.test/\u{1b} https://a.test/\u{1b}x";
    let mut counts = Counts::default();
    let mut index = index_from(&[], Vec::new());
    collect_indexed(&URL_RULE, text, 0, &limits, Vec::new(), &mut index, &mut counts);
    assert_eq!(index.hosts, ["a.test"]);
    assert_eq!(counts.urls_dropped, 1);
    assert_eq!(counts.url_cap_reached, 1);
    Ok(())
}


#[test]
fn hitting_the_url_cap_is_named_in_the_record_and_not_otherwise() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        urls: 1,
        ..Limits::default()
    };
    let mut counts = Counts::default();
    let found = collect(&URL_RULE, "http://a.test/ http://a.test/", 0, &limits, Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://a.test/"]);
    assert_eq!(counts.url_cap_reached, 0);
    let more = collect(&URL_RULE, "http://b.test/", 0, &limits, found, &mut counts);
    assert_eq!(more.len(), 1);
    assert_eq!((counts.urls_dropped, counts.url_cap_reached), (1, 1));
    Ok(())
}


#[test]
fn a_cleaned_url_is_kept_before_its_truncated_form_for_the_last_slot() -> Result<(), Box<dyn std::error::Error>> {
    let limits = Limits {
        urls: 1,
        ..Limits::default()
    };
    let mut counts = Counts::default();
    let text = html_text("<a href='http://h.test/a&#9;b'>", &mut counts);
    let found = collect(&URL_RULE, &text, 0, &limits, Vec::new(), &mut counts);
    assert_eq!(links(&found), ["http://h.test/ab"]);
    Ok(())
}


#[test]
fn a_known_url_from_an_earlier_level_is_not_listed_again() -> Result<(), Box<dyn std::error::Error>> {
    let known = vec![UrlHit {
        level: 0,
        url: "http://k.test/".to_owned(),
    }];
    let mut counts = Counts::default();
    let found = collect(&URL_RULE, "http://k.test/ http://n.test/", 1, &Limits::default(), known, &mut counts);
    assert_eq!(links(&found), ["http://k.test/", "http://n.test/"]);
    Ok(())
}
