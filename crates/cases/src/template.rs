use crate::error::{CreateError, TemplateError, TemplateLoadError};
use crate::model::{Case, CaseStatus, Severity, Task, TaskAction, TaskLogEntry, TaskStatus};
use core_config::load::load_file;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;


pub const MAX_TEMPLATES: usize = 100;


pub const MAX_TASKS_PER_TEMPLATE: usize = 50;


/// One year.
pub const MAX_DUE_HOURS: u32 = 8760;


const SECONDS_PER_HOUR: i64 = 3600;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseField {
    Title,
    Assignee,
    Description,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskTemplate {
    pub title: String,
    pub due_hours: Option<u32>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTemplate {
    pub name: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub tasks: Vec<TaskTemplate>,
    #[serde(default)]
    pub mandatory_fields: Vec<CaseField>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFile {
    pub templates: Vec<CaseTemplate>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseDraft {
    pub tenant: String,
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    pub assignee: Option<String>,
    pub case_type: Option<String>,
}


pub fn check(condition: bool, error: TemplateError) -> Result<(), TemplateError> {
    condition.then_some(()).ok_or(error)
}


pub fn validate_task(template: &str, task: &TaskTemplate) -> Result<(), TemplateError> {
    check(!task.title.trim().is_empty(), TemplateError::EmptyTaskTitle(template.to_string()))?;
    let hours = task.due_hours.unwrap_or(0);
    check(
        hours <= MAX_DUE_HOURS,
        TemplateError::DueOutOfRange {
            template: template.to_string(),
            hours,
            max: MAX_DUE_HOURS,
        },
    )
}


pub fn validate_template(template: &CaseTemplate) -> Result<(), TemplateError> {
    check(!template.name.trim().is_empty(), TemplateError::EmptyName)?;
    check(
        template.tasks.len() <= MAX_TASKS_PER_TEMPLATE,
        TemplateError::TooManyTasks {
            template: template.name.clone(),
            max: MAX_TASKS_PER_TEMPLATE,
        },
    )?;
    template.tasks.iter().try_for_each(|task| validate_task(&template.name, task))
}


pub fn validate_templates(file: TemplateFile) -> Result<Vec<CaseTemplate>, TemplateError> {
    check(
        file.templates.len() <= MAX_TEMPLATES,
        TemplateError::TooManyTemplates { max: MAX_TEMPLATES },
    )?;
    file.templates.iter().try_for_each(validate_template)?;
    file.templates.iter().try_fold(BTreeSet::new(), |mut seen, template| {
        seen.insert(template.name.as_str())
            .then_some(seen)
            .ok_or_else(|| TemplateError::DuplicateName(template.name.clone()))
    })?;
    Ok(file.templates)
}


/// Strict YAML through core-config (errors name file, line and field), then the bounds.
pub fn load_templates(path: &Path) -> Result<Vec<CaseTemplate>, TemplateLoadError> {
    let file: TemplateFile = load_file(path)?;
    Ok(validate_templates(file)?)
}


pub fn find_template<'a>(templates: &'a [CaseTemplate], name: &str) -> Option<&'a CaseTemplate> {
    templates.iter().find(|template| template.name == name)
}


pub fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|text| text.trim().is_empty())
}


pub fn is_missing(draft: &CaseDraft, field: CaseField) -> bool {
    match field {
        CaseField::Title => is_blank(Some(&draft.title)),
        CaseField::Assignee => is_blank(draft.assignee.as_deref()),
        CaseField::Description => is_blank(draft.description.as_deref()),
    }
}


pub fn task_from_template(task: &TaskTemplate, actor: &str, now: i64) -> Task {
    Task {
        title: task.title.clone(),
        status: TaskStatus::Todo,
        due: task.due_hours.map(|hours| now + i64::from(hours) * SECONDS_PER_HOUR),
        log: vec![TaskLogEntry {
            at: now,
            actor: actor.to_string(),
            action: TaskAction::Created,
        }],
    }
}


pub fn check_type(template: &CaseTemplate, case_type: Option<&String>) -> Result<(), CreateError> {
    match case_type {
        Some(name) if !template.types.is_empty() && !template.types.contains(name) => Err(CreateError::TypeNotAllowed(name.clone())),
        _ => Ok(()),
    }
}


/// The title is always required; the template adds its mandatory fields. A missing one refuses the creation and lists all of them.
pub fn create_case(template: &CaseTemplate, draft: CaseDraft, id: String, actor: &str, now: i64) -> Result<Case, CreateError> {
    let required: BTreeSet<CaseField> = template.mandatory_fields.iter().copied().chain([CaseField::Title]).collect();
    let missing: Vec<CaseField> = required.into_iter().filter(|field| is_missing(&draft, *field)).collect();
    missing.is_empty().then_some(()).ok_or(CreateError::MissingFields(missing))?;
    check_type(template, draft.case_type.as_ref())?;
    Ok(Case {
        id,
        tenant: draft.tenant,
        title: draft.title,
        description: draft.description,
        severity: draft.severity,
        status: CaseStatus::New,
        resolution: None,
        assignee: draft.assignee,
        template: Some(template.name.clone()),
        case_type: draft.case_type,
        created_at: now,
        updated_at: now,
        tasks: template.tasks.iter().map(|task| task_from_template(task, actor, now)).collect(),
        observables: Vec::new(),
        comments: Vec::new(),
        history: Vec::new(),
    })
}
