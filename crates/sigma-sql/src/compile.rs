use crate::condition::compile_condition;
use crate::error::SigmaError;
use crate::mapping::FieldMapping;
use crate::rule::{parse_rule, Rule};
use crate::selection::{compile_selection, Context};
use crate::sql::{quote_identifier, sql_literal};
use crate::types::{FieldTable, SelectionSql};


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


pub const PROVIDER_COLUMN: &str = "`event.provider`";


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


struct Source<'a> {
    label: &'a str,
    fields: &'a FieldTable,
    filter: String,
}


fn logsource_source<'a>(rule: &'a Rule, mapping: &'a FieldMapping) -> Result<Source<'a>, SigmaError> {
    match (rule.logsource.category.as_deref(), rule.logsource.service.as_deref()) {
        (Some(category), None) => mapping
            .categories
            .get(category)
            .map(|found| Source {
                label: category,
                fields: &found.fields,
                filter: format!("has({CATEGORY_COLUMN}, {})", sql_literal(&found.event_category)),
            })
            .ok_or_else(|| unsupported(rule, format!("logsource category {category}"))),
        (None, Some(service)) => mapping
            .services
            .get(service)
            .map(|found| Source {
                label: service,
                fields: &found.fields,
                filter: format!("{PROVIDER_COLUMN} = {}", sql_literal(&found.provider)),
            })
            .ok_or_else(|| unsupported(rule, format!("logsource service {service}"))),
        (Some(_), Some(_)) => Err(unsupported(rule, "logsource with both category and service".to_string())),
        (None, None) => Err(unsupported(rule, "logsource without category or service".to_string())),
    }
}


/// Compiles one Sigma rule text to a `SELECT` of the matching event ids; the logsource becomes a filter on category or provider and operating system.
pub fn compile_rule(text: &str, mapping: &FieldMapping, options: &SqlOptions) -> Result<String, SigmaError> {
    let rule = parse_rule(text)?;
    let source = logsource_source(&rule, mapping)?;
    let context = Context {
        rule: &rule.title,
        category: source.label,
        fields: source.fields,
    };
    let selections: SelectionSql = rule
        .selections
        .iter()
        .map(|(name, value)| compile_selection(&context, value).map(|sql| (name.clone(), sql)))
        .collect::<Result<_, _>>()?;
    let condition = compile_condition(&rule.title, &rule.condition, &selections)?;
    let os = os_filter(&rule, mapping)?;
    let filters: Vec<String> = if rule.logsource.service.is_some() {
        os.into_iter().chain([source.filter, condition]).collect()
    } else {
        [source.filter].into_iter().chain(os).chain([condition]).collect()
    };
    Ok(format!(
        "SELECT {} FROM {} WHERE {}",
        quote_identifier(&options.id_column)?,
        quote_identifier(&options.table)?,
        filters.join(" AND ")
    ))
}
