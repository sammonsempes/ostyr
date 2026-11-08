use crate::error::SigmaError;
use crate::mapping::CategoryMapping;
use crate::modifier::{parse_field_key, Matcher, Modifiers};
use crate::sql::{is_array_field, quote_identifier, sql_literal};
use crate::value::{like_pattern, parse_pieces, plain_text, Piece};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::net::IpAddr;


pub struct Context<'a> {
    pub rule: &'a str,
    pub category: &'a str,
    pub mapping: &'a CategoryMapping,
}


const DASH_VARIANTS: &[char] = &['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];


const ARRAY_ELEMENT: &str = "x";


const IPV4_BITS: u8 = 32;


const IPV6_BITS: u8 = 128;


fn bad_value(context: &Context, field: &str, reason: String) -> SigmaError {
    SigmaError::BadValue {
        rule: context.rule.to_string(),
        field: field.to_string(),
        reason,
    }
}


fn join(parts: &[String], separator: &str) -> String {
    match parts {
        [only] => only.clone(),
        _ => format!("({})", parts.join(separator)),
    }
}


fn joined(context: &Context, parts: &[String], separator: &str) -> Result<String, SigmaError> {
    if parts.is_empty() {
        Err(SigmaError::Unsupported {
            rule: context.rule.to_string(),
            construct: "empty selection or value list".to_string(),
        })
    } else {
        Ok(join(parts, separator))
    }
}


fn check_cidr(text: &str) -> Result<(), String> {
    let (address, prefix) = text.split_once('/').ok_or("expected address/prefix")?;
    let parsed: IpAddr = address.parse().map_err(|error: std::net::AddrParseError| error.to_string())?;
    let bits: u8 = prefix.parse().map_err(|error: std::num::ParseIntError| error.to_string())?;
    let maximum = if parsed.is_ipv4() { IPV4_BITS } else { IPV6_BITS };
    if bits <= maximum {
        Ok(())
    } else {
        Err(format!("prefix longer than {maximum} bits"))
    }
}


fn like(column: &str, pieces: &[Piece], open_start: bool, open_end: bool) -> String {
    format!("{column} ilike {}", sql_literal(&like_pattern(pieces, open_start, open_end)))
}


fn matcher_sql(context: &Context, field: &str, column: &str, matcher: Matcher, text: &str) -> Result<String, SigmaError> {
    let pieces = parse_pieces(text);
    match matcher {
        Matcher::Equals => Ok(like(column, &pieces, false, false)),
        Matcher::Contains => Ok(like(column, &pieces, true, true)),
        Matcher::StartsWith => Ok(like(column, &pieces, false, true)),
        Matcher::EndsWith => Ok(like(column, &pieces, true, false)),
        Matcher::Regex => Regex::new(text)
            .map(|_| format!("match({column}, {})", sql_literal(text)))
            .map_err(|error| bad_value(context, field, error.to_string())),
        Matcher::Cidr => check_cidr(text)
            .map(|()| format!("isIPAddressInRange(toString({column}), {})", sql_literal(text)))
            .map_err(|reason| bad_value(context, field, reason)),
        Matcher::Exists => Err(bad_value(context, field, "exists takes true or false".to_string())),
    }
}


fn dash_variants(text: &str) -> Vec<String> {
    let variants: BTreeSet<String> = DASH_VARIANTS.iter().map(|dash| text.replace('-', &dash.to_string())).collect();
    variants.into_iter().collect()
}


fn text_sql(context: &Context, field: &str, column: &str, modifiers: Modifiers, text: &str) -> Result<String, SigmaError> {
    let variants = if modifiers.windash {
        dash_variants(text)
    } else {
        vec![text.to_string()]
    };
    let parts = variants
        .iter()
        .map(|variant| matcher_sql(context, field, column, modifiers.matcher, variant))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(join(&parts, " OR "))
}


fn item_sql(context: &Context, field: &str, column: &str, modifiers: Modifiers, item: &Value) -> Result<String, SigmaError> {
    match (modifiers.matcher, item) {
        (Matcher::Exists, Value::Bool(present)) => Ok(format!("{}({column})", if *present { "isNotNull" } else { "isNull" })),
        (Matcher::Equals, Value::Null) => Ok(format!("isNull({column})")),
        (Matcher::Equals, Value::Bool(flag)) => Ok(format!("{column} = {flag}")),
        (Matcher::Equals, Value::Number(number)) => Ok(format!("{column} = {number}")),
        (_, Value::String(text)) => text_sql(context, field, column, modifiers, text),
        (_, Value::Number(number)) => text_sql(context, field, column, modifiers, &number.to_string()),
        _ => Err(bad_value(context, field, "unsupported value type".to_string())),
    }
}


fn array_item_sql(context: &Context, field: &str, column: &str, modifiers: Modifiers, item: &Value) -> Result<String, SigmaError> {
    let plain = match item {
        Value::String(text) if modifiers.matcher == Matcher::Equals && !modifiers.windash => plain_text(&parse_pieces(text)),
        _ => None,
    };
    match (modifiers.matcher, item, plain) {
        (Matcher::Exists, Value::Bool(present), _) => Ok(format!("{}({column})", if *present { "notEmpty" } else { "empty" })),
        (Matcher::Equals, Value::Null, _) => Ok(format!("empty({column})")),
        (Matcher::Equals, Value::Bool(flag), _) => Ok(format!("has({column}, {flag})")),
        (Matcher::Equals, Value::Number(number), _) => Ok(format!("has({column}, {number})")),
        (_, _, Some(text)) => Ok(format!("has({column}, {})", sql_literal(&text))),
        (_, Value::String(_) | Value::Number(_), None) => {
            item_sql(context, field, ARRAY_ELEMENT, modifiers, item).map(|predicate| format!("arrayExists({ARRAY_ELEMENT} -> {predicate}, {column})"))
        }
        _ => Err(bad_value(context, field, "unsupported value type".to_string())),
    }
}


fn has_any_sql(column: &str, modifiers: Modifiers, items: &[&Value]) -> Option<String> {
    let texts: Option<Vec<String>> = items
        .iter()
        .map(|item| match item {
            Value::String(text) => plain_text(&parse_pieces(text)).map(|plain| sql_literal(&plain)),
            _ => None,
        })
        .collect();
    texts
        .filter(|list| list.len() > 1 && modifiers.matcher == Matcher::Equals && !modifiers.all && !modifiers.windash)
        .map(|list| format!("hasAny({column}, [{}])", list.join(", ")))
}


fn compile_field(context: &Context, key: &str, value: &Value) -> Result<String, SigmaError> {
    let (field, modifiers) = parse_field_key(context.rule, key)?;
    let column = context.mapping.fields.get(&field).ok_or_else(|| SigmaError::UnmappedField {
        rule: context.rule.to_string(),
        field: field.clone(),
        category: context.category.to_string(),
    })?;
    let quoted = quote_identifier(column)?;
    let items: Vec<&Value> = match value {
        Value::Array(list) => list.iter().collect(),
        single => vec![single],
    };
    let array = is_array_field(column);
    let any = if array { has_any_sql(&quoted, modifiers, &items) } else { None };
    let parts = match any {
        Some(sql) => vec![sql],
        None => items
            .iter()
            .map(|item| {
                if array {
                    array_item_sql(context, &field, &quoted, modifiers, item)
                } else {
                    item_sql(context, &field, &quoted, modifiers, item)
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    joined(context, &parts, if modifiers.all { " AND " } else { " OR " })
}


fn compile_map(context: &Context, map: &Map<String, Value>) -> Result<String, SigmaError> {
    let parts = map
        .iter()
        .map(|(key, value)| compile_field(context, key, value))
        .collect::<Result<Vec<_>, _>>()?;
    joined(context, &parts, " AND ")
}


fn keyword_selection(context: &Context) -> SigmaError {
    SigmaError::Unsupported {
        rule: context.rule.to_string(),
        construct: "keyword selection".to_string(),
    }
}


fn compile_item(context: &Context, item: &Value) -> Result<String, SigmaError> {
    match item {
        Value::Object(map) => compile_map(context, map),
        _ => Err(keyword_selection(context)),
    }
}


/// Compiles one named selection: a map is an AND of fields, a list of maps is an OR of maps, a value list is an OR of values.
pub fn compile_selection(context: &Context, value: &Value) -> Result<String, SigmaError> {
    match value {
        Value::Object(map) => compile_map(context, map),
        Value::Array(items) => {
            let parts = items.iter().map(|item| compile_item(context, item)).collect::<Result<Vec<_>, _>>()?;
            joined(context, &parts, " OR ")
        }
        _ => Err(keyword_selection(context)),
    }
}
