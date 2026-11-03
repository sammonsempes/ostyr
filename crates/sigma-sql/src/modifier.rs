use crate::error::SigmaError;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matcher {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Cidr,
    Exists,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifiers {
    pub matcher: Matcher,
    pub all: bool,
    pub windash: bool,
}


fn matcher_for(name: &str) -> Option<Matcher> {
    match name {
        "contains" => Some(Matcher::Contains),
        "startswith" => Some(Matcher::StartsWith),
        "endswith" => Some(Matcher::EndsWith),
        "re" => Some(Matcher::Regex),
        "cidr" => Some(Matcher::Cidr),
        "exists" => Some(Matcher::Exists),
        _ => None,
    }
}


fn unsupported(rule: &str, construct: String) -> SigmaError {
    SigmaError::Unsupported {
        rule: rule.to_string(),
        construct,
    }
}


fn apply(rule: &str, field: &str, current: Modifiers, name: &str) -> Result<Modifiers, SigmaError> {
    match (name, matcher_for(name)) {
        ("all", _) if !current.all => Ok(Modifiers { all: true, ..current }),
        ("windash", _) if !current.windash => Ok(Modifiers { windash: true, ..current }),
        (_, Some(matcher)) if current.matcher == Matcher::Equals => Ok(Modifiers { matcher, ..current }),
        (_, Some(_)) => Err(unsupported(rule, format!("conflicting modifiers on {field}"))),
        _ => Err(SigmaError::UnknownModifier {
            rule: rule.to_string(),
            field: field.to_string(),
            modifier: name.to_string(),
        }),
    }
}


/// Splits `Field|mod|mod` into the field name and its modifiers; unknown, repeated or conflicting modifiers are refused.
pub fn parse_field_key(rule: &str, key: &str) -> Result<(String, Modifiers), SigmaError> {
    let (field, names): (&str, Vec<&str>) = match key.split_once('|') {
        Some((field, chain)) => (field, chain.split('|').collect()),
        None => (key, Vec::new()),
    };
    let start = Modifiers {
        matcher: Matcher::Equals,
        all: false,
        windash: false,
    };
    let modifiers = names.iter().try_fold(start, |current, name| apply(rule, field, current, name))?;
    let plain_only = matches!(modifiers.matcher, Matcher::Regex | Matcher::Cidr | Matcher::Exists);
    if field.is_empty() {
        Err(unsupported(rule, "empty field name".to_string()))
    } else if plain_only && modifiers.windash {
        Err(unsupported(rule, format!("windash on {field} with a non-string matcher")))
    } else {
        Ok((field.to_string(), modifiers))
    }
}
