use crate::base::{compile_base, BaseRule};
use crate::correlation::{check_keys, invalid, parse_kind, parse_timespan, CorrelationRule, RawDocument};
use crate::error::{schema_error, CorrelationError};
use crate::types::RuleTexts;
use core_config::error::ConfigError;
use core_config::parse::parse_document;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sigma_sql::mapping::FieldMapping;
use std::collections::{BTreeMap, BTreeSet};


pub const DOCUMENT_SEPARATOR: &str = "---";


pub const CORRELATION_KEY: &str = "correlation";


#[derive(Debug, Clone)]
pub struct RuleSet {
    pub bases: Vec<BaseRule>,
    pub correlations: Vec<CorrelationRule>,
}


#[derive(Debug, Clone)]
pub struct Document {
    pub file: String,
    pub text: String,
    pub value: Value,
}


/// Names the file in an error; a redacted YAML error carries the file in its own fields.
pub fn in_file(file: &str, source: CorrelationError) -> CorrelationError {
    match source {
        CorrelationError::Config(ConfigError::Parse {
            line,
            column,
            field_path,
            message,
            source: cause,
            ..
        }) => CorrelationError::Config(ConfigError::Parse {
            file: file.to_string(),
            line,
            column,
            field_path,
            message,
            source: cause,
        }),
        other => CorrelationError::InFile {
            file: file.to_string(),
            source: Box::new(other),
        },
    }
}


/// Splits a file into its YAML documents on `---` lines and drops blank ones.
pub fn split_documents(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    lines
        .split(|line| line.trim_end() == DOCUMENT_SEPARATOR)
        .map(|chunk| chunk.join("\n"))
        .filter(|document| !document.trim().is_empty())
        .collect()
}


fn read_documents(texts: &RuleTexts) -> Result<Vec<Document>, CorrelationError> {
    texts.iter().try_fold(Vec::new(), |mut documents, (file, text)| {
        split_documents(text).into_iter().try_for_each(|document| {
            parse_document::<Value>(&document, file)
                .map(|value| {
                    documents.push(Document {
                        file: file.clone(),
                        text: document,
                        value,
                    })
                })
                .map_err(CorrelationError::from)
        })?;
        Ok(documents)
    })
}


fn compile_bases(documents: &[&Document], mapping: &FieldMapping) -> Result<Vec<BaseRule>, CorrelationError> {
    documents
        .iter()
        .map(|document| {
            let name = document.value.get("name").and_then(Value::as_str).map(str::to_string);
            compile_base(&document.text, name, mapping).map_err(|error| in_file(&document.file, error))
        })
        .collect()
}


/// Maps every `id` and `name` of a base rule to its position; an identifier used twice is refused.
pub fn index_references(bases: &[BaseRule]) -> Result<BTreeMap<String, usize>, CorrelationError> {
    bases.iter().enumerate().try_fold(BTreeMap::new(), |mut index, (position, base)| {
        let keys: BTreeSet<&String> = base.id.iter().chain(base.name.iter()).collect();
        keys.into_iter().try_for_each(|key| match index.insert(key.clone(), position) {
            Some(_) => Err(CorrelationError::Duplicate(key.clone())),
            None => Ok(()),
        })?;
        Ok(index)
    })
}


pub fn fingerprint(text: &str, bases: &[&BaseRule]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    bases.iter().for_each(|base| hasher.update(base.source.as_bytes()));
    format!("{:x}", hasher.finalize())
}


fn compile_correlation(document: &Document, references: &BTreeMap<String, usize>, bases: &[BaseRule]) -> Result<CorrelationRule, CorrelationError> {
    let title = document.value.get("title").and_then(Value::as_str).unwrap_or("untitled");
    let raw: RawDocument = serde_path_to_error::deserialize(document.value.clone()).map_err(|error| schema_error(title, &error))?;
    check_keys(&raw)?;
    let kind = parse_kind(&raw.title, &raw.correlation)?;
    let timespan_ms = parse_timespan(&raw.title, &raw.correlation.timespan)?;
    let rules = raw
        .correlation
        .rules
        .iter()
        .map(|reference| {
            references
                .get(reference)
                .copied()
                .ok_or_else(|| CorrelationError::UnknownReference { rule: raw.title.clone() })
        })
        .collect::<Result<Vec<usize>, _>>()?;
    match rules.as_slice() {
        [] => Err(invalid(&raw.title, "rules", "at least one rule is required".to_string())),
        _ => Ok(()),
    }?;
    let referenced: Vec<&BaseRule> = rules.iter().filter_map(|position| bases.get(*position)).collect();
    Ok(CorrelationRule {
        id: raw.id.or(raw.name).unwrap_or_else(|| raw.title.clone()),
        fingerprint: fingerprint(&document.text, &referenced),
        title: raw.title,
        kind,
        rules,
        group_by: raw.correlation.group_by,
        timespan_ms,
        generate: raw.correlation.generate,
        source: document.text.clone(),
    })
}


fn check_unique_ids(correlations: &[CorrelationRule]) -> Result<(), CorrelationError> {
    correlations.iter().try_fold(BTreeSet::new(), |mut seen, rule| {
        if seen.insert(rule.id.clone()) {
            Ok(seen)
        } else {
            Err(CorrelationError::Duplicate(rule.id.clone()))
        }
    })?;
    Ok(())
}


/// Parses every document of every file: documents with a `correlation` key are correlation rules, the others single-event base rules.
pub fn parse_ruleset(texts: &RuleTexts, mapping: &FieldMapping) -> Result<RuleSet, CorrelationError> {
    let documents = read_documents(texts)?;
    let (correlation_documents, base_documents): (Vec<&Document>, Vec<&Document>) =
        documents.iter().partition(|document| document.value.get(CORRELATION_KEY).is_some());
    let bases = compile_bases(&base_documents, mapping)?;
    let references = index_references(&bases)?;
    let correlations = correlation_documents
        .iter()
        .map(|document| compile_correlation(document, &references, &bases).map_err(|error| in_file(&document.file, error)))
        .collect::<Result<Vec<_>, _>>()?;
    check_unique_ids(&correlations)?;
    Ok(RuleSet { bases, correlations })
}
