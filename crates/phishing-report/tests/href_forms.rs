use phishing_report::limits::Limits;
use phishing_report::model::{Counts, UrlHit};
use phishing_report::urls::{collect, html_text, html_text_with, ATTRIBUTE_RULE, URL_RULE};
use regex::Regex;


const MANY_REFERENCES: usize = 200_000;


const ZEROS: usize = 100_000;


const REFUSED_FORMS: usize = 3;


const LOST_FORMS: usize = 6;


fn found_in(html: &str, counts: &mut Counts) -> Vec<UrlHit> {
    let text = html_text(html, counts);
    collect(&URL_RULE, &text, 0, &Limits::default(), Vec::new(), counts)
}


fn links(found: &[UrlHit]) -> Vec<&str> {
    found.iter().map(|hit| hit.url.as_str()).collect()
}


#[test]
fn every_form_a_browser_follows_is_listed() -> Result<(), Box<dyn std::error::Error>> {
    let forms = [
        (
            "<a href='&#0000000000000000000000000000000000000104;ttps://lz.evil.test/1'>",
            "https://lz.evil.test/1",
        ),
        ("<a href='&#X68;ttps://ux.evil.test/2'>", "https://ux.evil.test/2"),
        ("<a href='ht&#9;tps://tab.evil.test/3'>", "https://tab.evil.test/3"),
        ("<a href='ht&Tab;tps://ntab.evil.test/4'>", "https://ntab.evil.test/4"),
        ("<a href='ht&NewLine;tps://nl.evil.test/5'>", "https://nl.evil.test/5"),
        ("<a href='ht\ttps://rawtab.evil.test/6'>", "https://rawtab.evil.test/6"),
        ("<a href='https:&sol;&sol;sol.evil.test/7'>", "https://sol.evil.test/7"),
        ("<a href='&#104ttps://nosemi.evil.test/9'>", "https://nosemi.evil.test/9"),
        ("<a href='&#x68ttps://nosemix.evil.test/9'>", "https://nosemix.evil.test/9"),
        ("<a href='https&#58//colon.evil.test/8'>", "https://colon.evil.test/8"),
        ("<a href=' https://space.evil.test/10'>", "https://space.evil.test/10"),
        ("<a href=\"&#32;&#9;https://edge.evil.test/10\">", "https://edge.evil.test/10"),
        ("<a href='https:/\\bs.evil.test/13'>", "https://bs.evil.test/13"),
        ("<a href=https:\\\\bare.evil.test\\p>", "https://bare.evil.test/p"),
        ("<a href='https://mid.evil.test/a&#9;b&#10;c'>", "https://mid.evil.test/abc"),
        ("<a href=\"h\nt\ntp://nl2.evil.test/x\">", "http://nl2.evil.test/x"),
        ("<a href='HTTPS://UP.EVIL.TEST/11'>", "https://up.evil.test/11"),
    ];
    forms.iter().try_for_each(|(html, expected)| {
        let mut counts = Counts::default();
        let found = found_in(html, &mut counts);
        assert!(links(&found).contains(expected), "{html:?} gave {:?}", links(&found));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[test]
fn a_raw_tab_in_the_scheme_of_plain_text_is_stripped_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = collect(
        &URL_RULE,
        "see ht\ttps://tab.evil.test/x now",
        0,
        &Limits::default(),
        Vec::new(),
        &mut counts,
    );
    assert_eq!(links(&found), ["https://tab.evil.test/x"]);
    assert_eq!(counts.urls_cleaned, 1);
    Ok(())
}


#[test]
fn a_decoded_control_or_bidi_character_refuses_the_url_and_counts_it() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = found_in(
        "<a href='https://esc.evil.test/&#27;x'> <a href='https://bidi.evil.test/&#x202E;x'> <a href='https://bidi2.evil.test/&#8238x'>",
        &mut counts,
    );
    assert!(found.is_empty());
    assert_eq!(counts.urls_refused, REFUSED_FORMS);
    Ok(())
}


#[test]
fn a_tab_removed_by_the_browser_is_not_a_hostile_character() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = found_in("<a href='https://tab.evil.test/a&#9;b'>", &mut counts);
    assert!(links(&found).contains(&"https://tab.evil.test/ab"));
    assert_eq!(counts.urls_refused, 0);
    Ok(())
}


#[test]
fn every_reference_that_cannot_be_decoded_is_counted_whatever_its_length() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    html_text("&bogus; &#; &#99999999999999999999; &#1114112; &#xD800; &#0; &amp=b & done", &mut counts);
    assert_eq!(counts.html_refs_undecoded, LOST_FORMS);
    let mut long = Counts::default();
    html_text(&format!("&{};", "a".repeat(MANY_REFERENCES)), &mut long);
    assert_eq!(long.html_refs_undecoded, 1);
    let mut literal = Counts::default();
    html_text("already \u{FFFD} replaced", &mut literal);
    assert_eq!(literal.html_refs_undecoded, 0);
    Ok(())
}


#[test]
fn two_hundred_thousand_references_are_all_counted() -> Result<(), Box<dyn std::error::Error>> {
    let mut overflow = Counts::default();
    html_text(&"&#99999999999;".repeat(MANY_REFERENCES), &mut overflow);
    assert_eq!(overflow.html_refs_undecoded, MANY_REFERENCES);
    let mut unknown = Counts::default();
    html_text(&"&bogus;".repeat(MANY_REFERENCES), &mut unknown);
    assert_eq!(unknown.html_refs_undecoded, MANY_REFERENCES);
    let mut bare = Counts::default();
    html_text(&"&".repeat(MANY_REFERENCES), &mut bare);
    assert_eq!(bare.html_refs_undecoded, 0);
    let mut quotes = Counts::default();
    html_text(&"='".repeat(MANY_REFERENCES), &mut quotes);
    assert_eq!(quotes.html_refs_undecoded, 0);
    Ok(())
}


#[test]
fn a_huge_run_of_leading_zeros_is_one_reference() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = found_in(&format!("<a href='&#{}104;ttps://zeros.evil.test/'>", "0".repeat(ZEROS)), &mut counts);
    assert_eq!(links(&found), ["https://zeros.evil.test/"]);
    assert_eq!(counts.html_refs_undecoded, 0);
    Ok(())
}


#[test]
fn an_attribute_a_browser_reads_as_written_is_not_listed_twice() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = found_in(
        "<a href=\"https://a.example/x\"><a href='https://b.example/y'><a href=https://c.example/z>",
        &mut counts,
    );
    assert_eq!(links(&found), ["https://a.example/x", "https://b.example/y", "https://c.example/z"]);
    Ok(())
}


#[test]
fn a_pattern_that_did_not_compile_re_reads_no_attribute_and_is_counted() -> Result<(), Box<dyn std::error::Error>> {
    let broken = Regex::new(&String::from("("));
    let mut counts = Counts::default();
    let text = html_text_with(&broken, "<a href='ht&#9;tps://x.evil.test/'>", &mut counts);
    assert_eq!(counts.pattern_failed, 1);
    assert!(!text.contains("\nhttps"));
    let mut fine = Counts::default();
    let reread = html_text_with(&ATTRIBUTE_RULE, "<a href='ht&#9;tps://x.evil.test/'>", &mut fine);
    assert!(reread.contains("\nhttps://x.evil.test/"));
    assert_eq!(fine.pattern_failed, 0);
    Ok(())
}
