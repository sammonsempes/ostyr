use crate::condition::compile_condition;
use crate::error::SigmaError;
use crate::mapping::FieldMapping;
use crate::rule::{parse_rule, Rule};
use crate::selection::{compile_selection, Context};
use crate::sql::{quote_identifier, sql_literal};
use crate::types::SelectionSql;


#[derive(Debug, Clone)]
pub struct SqlOptions {
    pub table: String,
    pub id_column: String,
}


impl Default for SqlOptions {
    fn default() -> Self {
        Self {
            table: "events".to_string(),
            id_column: "event.id".to_string(),
        }
    }
}


pub const CATEGORY_COLUMN: &str = "`event.category`";


pub const OS_COLUMN: &str = "`host.os.type`";


fn unsupported(rule: &Rule, construct: String) -> SigmaError {
    SigmaError::Unsupported {
        rule: rule.title.clone(),
        construct,
    }
}


fn os_filter(rule: &Rule, mapping: &FieldMapping) -> Result<Vec<String>, SigmaError> {
    match rule.logsource.product.as_deref() {
        None => Ok(Vec::new()),
        Some(product) => mapping
            .products
            .get(product)
            .map(|os| vec![format!("{OS_COLUMN} = {}", sql_literal(os))])
            .ok_or_else(|| unsupported(rule, format!("logsource product {product}"))),
    }
}


/// Compiles one Sigma rule text to a `SELECT` of the matching event ids; the logsource becomes a filter on category and operating system.
pub fn compile_rule(text: &str, mapping: &FieldMapping, options: &SqlOptions) -> Result<String, SigmaError> {
    let rule = parse_rule(text)?;
    let category = rule
        .logsource
        .category
        .as_deref()
        .ok_or_else(|| unsupported(&rule, "logsource without category".to_string()))?;
    let category_mapping = mapping
        .categories
        .get(category)
        .ok_or_else(|| unsupported(&rule, format!("logsource category {category}")))?;
    match rule.logsource.service {
        Some(_) => Err(unsupported(&rule, "logsource service".to_string())),
        None => Ok(()),
    }?;
    let context = Context {
        rule: &rule.title,
        category,
        mapping: category_mapping,
    };
    let selections: SelectionSql = rule
        .selections
        .iter()
        .map(|(name, value)| compile_selection(&context, value).map(|sql| (name.clone(), sql)))
        .collect::<Result<_, _>>()?;
    let condition = compile_condition(&rule.title, &rule.condition, &selections)?;
    let mut filters = vec![format!("has({CATEGORY_COLUMN}, {})", sql_literal(&category_mapping.event_category))];
    filters.extend(os_filter(&rule, mapping)?);
    filters.push(condition);
    Ok(format!(
        "SELECT {} FROM {} WHERE {}",
        quote_identifier(&options.id_column)?,
        quote_identifier(&options.table)?,
        filters.join(" AND ")
    ))
}
