#[path = "support/types.rs"]
mod types;


use sigma_sql::compile::{compile_rule, SqlOptions};
use sigma_sql::error::SigmaError;
use sigma_sql::mapping::parse_mapping;
use sigma_sql::sql::is_array_field;
use types::TestResult;


const ARRAY_MAPPING: &str = "products: {}\ncategories:\n  c:\n    event_category: process\n    fields:\n      Kind: event.type\n      Ip: related.ip\n      Name: user.name\n";


fn array_sql(detection: &str) -> Result<String, SigmaError> {
    let text = format!("title: Arrays\nlogsource:\n  category: c\ndetection:\n  selection:\n    {detection}\n  condition: selection\n");
    compile_rule(&text, &parse_mapping(ARRAY_MAPPING)?, &SqlOptions::default())
}


fn where_of(sql: &str) -> Result<String, String> {
    sql.split_once(" AND ")
        .map(|(_, rest)| rest.to_string())
        .ok_or_else(|| format!("no filter in {sql}"))
}


#[test]
fn array_fields_use_has_and_friends() -> TestResult {
    let cases = [
        ("Kind: start", "has(`event.type`, 'start')"),
        ("Kind: [start, end]", "hasAny(`event.type`, ['start', 'end'])"),
        ("Kind: [start]", "has(`event.type`, 'start')"),
        ("Kind: [start, 5]", "(has(`event.type`, 'start') OR has(`event.type`, 5))"),
        (
            "Kind: [start, 'e*']",
            "(has(`event.type`, 'start') OR arrayExists(x -> x ilike 'e%', `event.type`))",
        ),
        ("Kind|all: [start, end]", "(has(`event.type`, 'start') AND has(`event.type`, 'end'))"),
        ("Kind: 7", "has(`event.type`, 7)"),
        ("Kind: true", "has(`event.type`, true)"),
        ("Kind: null", "empty(`event.type`)"),
        ("Kind|exists: true", "notEmpty(`event.type`)"),
        ("Kind|exists: false", "empty(`event.type`)"),
        ("Kind: 'st*'", "arrayExists(x -> x ilike 'st%', `event.type`)"),
        ("Kind|contains: art", "arrayExists(x -> x ilike '%art%', `event.type`)"),
        ("Kind|startswith: st", "arrayExists(x -> x ilike 'st%', `event.type`)"),
        ("Kind|endswith: rt", "arrayExists(x -> x ilike '%rt', `event.type`)"),
        ("Kind|re: '^st'", "arrayExists(x -> match(x, '^st'), `event.type`)"),
        (
            "Ip|cidr: 10.0.0.0/8",
            "arrayExists(x -> isIPAddressInRange(toString(x), '10.0.0.0/8'), `related.ip`)",
        ),
        (
            "Kind|contains: [a, b]",
            "(arrayExists(x -> x ilike '%a%', `event.type`) OR arrayExists(x -> x ilike '%b%', `event.type`))",
        ),
        ("Kind|contains: 5", "arrayExists(x -> x ilike '%5%', `event.type`)"),
    ];
    cases.iter().try_for_each(|(detection, expected)| -> TestResult {
        assert_eq!(where_of(&array_sql(detection)?)?, format!("({expected})"), "{detection}");
        Ok(())
    })
}


#[test]
fn windash_on_an_array_field_ors_the_variants() -> TestResult {
    let sql = where_of(&array_sql("Kind|windash: a-b")?)?;
    assert!(sql.starts_with("(arrayExists(x -> (x ilike 'a-b' OR x ilike 'a/b'"), "{sql}");
    let list = where_of(&array_sql("Kind|windash: [a-b, c]")?)?;
    assert!(!list.contains("hasAny"), "{list}");
    Ok(())
}


#[test]
fn scalar_and_array_fields_mix() -> TestResult {
    let sql = array_sql("Name|contains: bob\n    Kind: start")?;
    assert!(
        sql.ends_with("WHERE has(`event.category`, 'process') AND ((has(`event.type`, 'start') AND `user.name` ilike '%bob%'))"),
        "{sql}"
    );
    Ok(())
}


#[test]
fn scalar_fields_are_unchanged() -> TestResult {
    assert_eq!(where_of(&array_sql("Name: bob")?)?, "(`user.name` ilike 'bob')");
    assert_eq!(where_of(&array_sql("Name: null")?)?, "(isNull(`user.name`))");
    assert!(is_array_field("tags"));
    assert!(!is_array_field("user.name"));
    Ok(())
}


#[test]
fn array_fields_refuse_odd_values() -> TestResult {
    assert!(matches!(array_sql("Kind: {a: b}"), Err(SigmaError::BadValue { .. })));
    assert!(matches!(array_sql("Kind|exists: 3"), Err(SigmaError::BadValue { .. })));
    assert!(matches!(array_sql("Kind|re: '('"), Err(SigmaError::BadValue { .. })));
    Ok(())
}
