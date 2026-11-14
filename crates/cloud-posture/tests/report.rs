#[path = "common/types.rs"]
mod types;


use cloud_posture::model::{Finding, Severity, Status};
use cloud_posture::report::fail_line;
use types::TestResult;


const CUT: usize = 7;


fn finding(resource_uid: &str, title: &str) -> Finding {
    Finding {
        uid: "u\u{0}1".to_owned(),
        check_id: "c".to_owned(),
        status: Status::Fail,
        severity: Severity::High,
        provider: "aws".to_owned(),
        account: "a".to_owned(),
        region: "r".to_owned(),
        resource_uid: resource_uid.to_owned(),
        resource_type: "Conditional Access Policy".to_owned(),
        time_unix: 1,
        title: title.to_owned(),
        title_cut: 0,
        detail: "d".to_owned(),
        detail_cut: CUT,
    }
}


#[test]
fn a_forged_field_in_a_text_stays_inside_its_quotes() -> TestResult {
    let line = fail_line(&finding("x title=forged", "a\" title=\"forged"));
    assert!(line.contains(r#"resource="x title=forged" type="Conditional Access Policy""#), "{line}");
    assert!(line.contains(r#"title="a\" title=\"forged" detail="d\\[7 bytes cut]""#), "{line}");
    assert!(line.contains(r#"uid="u\\u{0}1""#), "{line}");
    assert!(line.starts_with("FAIL High "), "{line}");
    Ok(())
}
