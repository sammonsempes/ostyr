use phishing_report::auth::{parse_header, split_fields, verdicts, CONFLICT, NO_TRUSTED_HEADER, OVERSIZED_HEADER, UNKNOWN};
use phishing_report::model::Counts;


const FOUR: usize = 4;


fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|id| (*id).to_owned()).collect()
}


fn read(texts: &[&str]) -> (phishing_report::model::AuthVerdicts, Counts) {
    let mut counts = Counts::default();
    let wrapped: Vec<Option<&str>> = texts.iter().map(|text| Some(*text)).collect();
    let found = verdicts(&wrapped, &ids(&["mx.corp.test"]), false, &mut counts);
    (found, counts)
}


#[test]
fn a_semicolon_inside_a_quoted_value_does_not_open_a_field() -> Result<(), Box<dyn std::error::Error>> {
    let (found, counts) = read(&["mx.corp.test; dkim=none; spf=fail smtp.mailfrom=\"x; dmarc=pass y\"@evil.test; dmarc=fail header.from=bank.test"]);
    assert_eq!((found.spf.as_str(), found.dkim.as_str(), found.dmarc.as_str()), ("fail", "none", "fail"));
    assert_eq!(found.reason, None);
    assert_eq!(counts, Counts::default());
    Ok(())
}


#[test]
fn quotes_comments_and_escapes_are_tokenised_per_rfc_8601() -> Result<(), Box<dyn std::error::Error>> {
    let fields = split_fields("a (c1 (nested; x) c2 \\) ; y) b; \"q\\\"; z\" ; \"q2\\\\\"; c(d)e").ok_or("balanced input refused")?;
    assert_eq!(fields, ["a   b", " \"q\\\"; z\" ", " \"q2\\\\\"", " c e"]);
    assert_eq!(split_fields("a; b").ok_or("refused")?, ["a", " b"]);
    Ok(())
}


#[test]
fn unbalanced_quotes_and_comments_refuse_the_header() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(split_fields("mx; x=\"open; dmarc=pass"), None);
    assert_eq!(split_fields("mx; (open; dmarc=pass"), None);
    assert_eq!(split_fields("mx; x=\\"), Some(vec!["mx".to_owned(), " x=\\".to_owned()]));
    assert_eq!(split_fields("mx; (a \\"), None);
    assert_eq!(split_fields("mx; \"a\\"), None);
    let (found, counts) = read(&["mx.corp.test; spf=pass; x=\"open", "mx.corp.test; dkim=fail"]);
    assert_eq!((found.spf.as_str(), found.dkim.as_str()), (UNKNOWN, "fail"));
    assert_eq!(counts.auth_refused, 1);
    Ok(())
}


#[test]
fn two_results_for_one_method_are_a_conflict_and_equal_ones_are_not() -> Result<(), Box<dyn std::error::Error>> {
    let (found, _) = read(&[
        "mx.corp.test; dmarc=fail header.from=a.test",
        "MX.Corp.Test; dmarc=pass; dkim=pass; dkim=pass; spf=pass",
    ]);
    assert_eq!(
        (found.spf.as_str(), found.dkim.as_str(), found.dmarc.as_str()),
        ("pass", "pass", CONFLICT)
    );
    let (single, _) = read(&["mx.corp.test; dkim=pass; dkim=fail"]);
    assert_eq!(single.dkim, CONFLICT);
    Ok(())
}


#[test]
fn a_header_without_a_trusted_id_gives_unknown_with_a_reason() -> Result<(), Box<dyn std::error::Error>> {
    let (found, counts) = read(&["forged.example; spf=pass; dkim=pass; dmarc=pass"]);
    assert_eq!(
        (found.spf.as_str(), found.dkim.as_str(), found.dmarc.as_str()),
        (UNKNOWN, UNKNOWN, UNKNOWN)
    );
    assert_eq!(found.reason.as_deref(), Some(NO_TRUSTED_HEADER));
    assert_eq!(counts.auth_untrusted, 1);
    let mut empty = Counts::default();
    let none = verdicts(&[Some("; spf=pass"), None], &ids(&["", "mx.corp.test"]), false, &mut empty);
    assert_eq!(none.reason.as_deref(), Some(NO_TRUSTED_HEADER));
    assert_eq!(empty.auth_refused, 1);
    let mut open = Counts::default();
    let without = verdicts(&[Some("mx.corp.test; spf=pass")], &[], false, &mut open);
    assert_eq!(without.spf, UNKNOWN);
    Ok(())
}


#[test]
fn an_oversized_header_gives_no_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let found = verdicts(&[Some("mx.corp.test; spf=pass")], &ids(&["mx.corp.test"]), true, &mut counts);
    assert_eq!(found.spf, UNKNOWN);
    assert_eq!(found.reason.as_deref(), Some(OVERSIZED_HEADER));
    Ok(())
}


#[test]
fn unknown_results_and_bad_methods_are_refused_and_counted() -> Result<(), Box<dyn std::error::Error>> {
    let (found, counts) = read(&["mx.corp.test; spf=maybe; dkim/1=Pass; dmarc = fail ; ba d=pass; =pass; arc=pass; none; dkim-atps=neutral; x="]);
    assert_eq!((found.spf.as_str(), found.dkim.as_str(), found.dmarc.as_str()), (UNKNOWN, "pass", "fail"));
    assert_eq!(counts.auth_refused, FOUR);
    Ok(())
}


#[test]
fn parse_header_reads_the_first_token_as_the_id() -> Result<(), Box<dyn std::error::Error>> {
    let mut counts = Counts::default();
    let parsed = parse_header("MX.Corp.Test 1; spf=pass", &mut counts).ok_or("refused")?;
    assert_eq!(parsed.id, "mx.corp.test");
    assert_eq!(parsed.results, [("spf".to_owned(), "pass".to_owned())]);
    let blank = parse_header("", &mut counts).ok_or("refused")?;
    assert_eq!(blank.id, "");
    Ok(())
}
