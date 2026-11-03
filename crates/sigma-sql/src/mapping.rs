use crate::error::SigmaError;
use crate::sql::quote_identifier;
use crate::types::FieldTable;
use serde::Deserialize;
use std::collections::BTreeMap;


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryMapping {
    pub event_category: String,
    pub fields: FieldTable,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMapping {
    pub products: FieldTable,
    pub categories: BTreeMap<String, CategoryMapping>,
}


/// Parses the mapping file and checks that every ECS column name is a plain identifier.
pub fn parse_mapping(text: &str) -> Result<FieldMapping, SigmaError> {
    let mapping: FieldMapping = serde_saphyr::from_str(text)?;
    mapping
        .categories
        .values()
        .flat_map(|category| category.fields.values())
        .try_for_each(|column| quote_identifier(column).map(|_| ()))?;
    Ok(mapping)
}
