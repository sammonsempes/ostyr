mod common;


use cases::error::{CreateError, TemplateError, TemplateLoadError};
use cases::model::{CaseStatus, Severity, TaskAction, TaskStatus};
use cases::template::{
    create_case, find_template, load_templates, validate_templates, CaseDraft, CaseField, CaseTemplate, TaskTemplate, TemplateFile, MAX_DUE_HOURS,
    MAX_TASKS_PER_TEMPLATE, MAX_TEMPLATES,
};
use common::types::TestResult;
use std::fs;
use tempfile::tempdir;


const NOW: i64 = 1_800_000_000;


const TWO_HOURS: i64 = 7_200;


const GOOD_YAML: &str = "templates:
  - name: phishing
    types: [email, user]
    mandatory_fields: [assignee]
    tasks:
      - title: Isolate mailbox
        due_hours: 2
      - title: Notify user
  - name: bare
";


fn template(name: &str) -> CaseTemplate {
    CaseTemplate {
        name: name.to_string(),
        types: Vec::new(),
        tasks: Vec::new(),
        mandatory_fields: Vec::new(),
    }
}


fn task(title: &str, due_hours: Option<u32>) -> TaskTemplate {
    TaskTemplate {
        title: title.to_string(),
        due_hours,
    }
}


fn draft() -> CaseDraft {
    CaseDraft {
        tenant: "acme".to_string(),
        severity: Severity::High,
        title: "Suspicious mail".to_string(),
        description: None,
        assignee: None,
        case_type: None,
    }
}


fn validate(templates: Vec<CaseTemplate>) -> Result<Vec<CaseTemplate>, TemplateError> {
    validate_templates(TemplateFile { templates })
}


#[test]
fn a_case_created_from_a_template_carries_its_tasks() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("templates.yaml");
    fs::write(&path, GOOD_YAML)?;
    let templates = load_templates(&path)?;
    let phishing = find_template(&templates, "phishing").ok_or("missing template")?;
    let created = create_case(
        phishing,
        CaseDraft {
            assignee: Some("alice".to_string()),
            case_type: Some("email".to_string()),
            ..draft()
        },
        "c1".to_string(),
        "alice",
        NOW,
    )?;
    assert_eq!(created.status, CaseStatus::New);
    assert_eq!(created.template.as_deref(), Some("phishing"));
    assert_eq!((created.created_at, created.updated_at), (NOW, NOW));
    let titles: Vec<&str> = created.tasks.iter().map(|task| task.title.as_str()).collect();
    assert_eq!(titles, ["Isolate mailbox", "Notify user"]);
    let dues: Vec<Option<i64>> = created.tasks.iter().map(|task| task.due).collect();
    assert_eq!(dues, [Some(NOW + TWO_HOURS), None]);
    let first = created.tasks.first().ok_or("no task")?;
    assert_eq!(first.status, TaskStatus::Todo);
    assert_eq!(first.log.first().map(|entry| entry.action), Some(TaskAction::Created));
    assert!(find_template(&templates, "absent").is_none());
    Ok(())
}


#[test]
fn missing_mandatory_fields_refuse_the_creation() -> TestResult {
    let mut strict = template("strict");
    strict.mandatory_fields = vec![CaseField::Assignee, CaseField::Description, CaseField::Title];
    let refused = create_case(
        &strict,
        CaseDraft {
            title: "  ".to_string(),
            ..draft()
        },
        "c1".to_string(),
        "alice",
        NOW,
    );
    assert_eq!(
        refused,
        Err(CreateError::MissingFields(vec![
            CaseField::Title,
            CaseField::Assignee,
            CaseField::Description
        ]))
    );
    assert!(refused.err().ok_or("expected an error")?.to_string().contains("Assignee"));
    let blank_assignee = CaseDraft {
        assignee: Some(" ".to_string()),
        description: Some("d".to_string()),
        ..draft()
    };
    assert_eq!(
        create_case(&strict, blank_assignee, "c1".to_string(), "alice", NOW),
        Err(CreateError::MissingFields(vec![CaseField::Assignee]))
    );
    Ok(())
}


#[test]
fn a_blank_title_is_refused_even_without_mandatory_fields() -> TestResult {
    let refused = create_case(
        &template("bare"),
        CaseDraft {
            title: String::new(),
            ..draft()
        },
        "c1".to_string(),
        "alice",
        NOW,
    );
    assert_eq!(refused, Err(CreateError::MissingFields(vec![CaseField::Title])));
    Ok(())
}


#[test]
fn the_case_type_must_belong_to_the_template() -> TestResult {
    let mut typed = template("typed");
    typed.types = vec!["email".to_string()];
    let wrong = CaseDraft {
        case_type: Some("malware".to_string()),
        ..draft()
    };
    assert_eq!(
        create_case(&typed, wrong.clone(), "c1".to_string(), "alice", NOW),
        Err(CreateError::TypeNotAllowed("malware".to_string()))
    );
    assert!(create_case(&template("free"), wrong, "c1".to_string(), "alice", NOW).is_ok());
    assert!(create_case(&typed, draft(), "c1".to_string(), "alice", NOW).is_ok());
    Ok(())
}


#[test]
fn bounds_and_duplicates_are_refused() -> TestResult {
    assert_eq!(validate(vec![template(" ")]), Err(TemplateError::EmptyName));
    assert_eq!(
        validate(vec![template("a"), template("b"), template("a")]),
        Err(TemplateError::DuplicateName("a".to_string()))
    );
    let mut with_empty_task = template("t");
    with_empty_task.tasks = vec![task(" ", None)];
    assert_eq!(validate(vec![with_empty_task]), Err(TemplateError::EmptyTaskTitle("t".to_string())));
    let mut far_due = template("t");
    far_due.tasks = vec![task("x", Some(MAX_DUE_HOURS + 1))];
    assert!(matches!(validate(vec![far_due]), Err(TemplateError::DueOutOfRange { .. })));
    let mut max_due = template("t");
    max_due.tasks = vec![task("x", Some(MAX_DUE_HOURS))];
    assert!(validate(vec![max_due]).is_ok());
    let mut many_tasks = template("t");
    many_tasks.tasks = (0..=MAX_TASKS_PER_TEMPLATE).map(|index| task(&format!("task {index}"), None)).collect();
    assert!(matches!(validate(vec![many_tasks.clone()]), Err(TemplateError::TooManyTasks { .. })));
    many_tasks.tasks.truncate(MAX_TASKS_PER_TEMPLATE);
    assert!(validate(vec![many_tasks]).is_ok());
    let many_templates: Vec<CaseTemplate> = (0..=MAX_TEMPLATES).map(|index| template(&format!("t{index}"))).collect();
    assert_eq!(validate(many_templates), Err(TemplateError::TooManyTemplates { max: MAX_TEMPLATES }));
    Ok(())
}


#[test]
fn error_messages_are_readable() -> TestResult {
    assert!(TemplateError::EmptyName.to_string().contains("empty"));
    assert!(TemplateError::DuplicateName("a".to_string()).to_string().contains('a'));
    assert!(TemplateError::TooManyTemplates { max: 1 }.to_string().contains("templates"));
    assert!(TemplateError::TooManyTasks {
        template: "t".to_string(),
        max: 1
    }
    .to_string()
    .contains("tasks"));
    assert!(TemplateError::EmptyTaskTitle("t".to_string()).to_string().contains("title"));
    assert!(CreateError::TypeNotAllowed("x".to_string()).to_string().contains('x'));
    Ok(())
}


#[test]
fn loading_errors_name_file_and_line() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("templates.yaml");
    fs::write(&path, "templates:\n  - name: a\n    colour: red\n")?;
    let message = load_templates(&path).err().ok_or("expected an error")?.to_string();
    assert!(message.contains("templates.yaml:3"), "{message}");
    assert!(message.contains("unknown field"), "{message}");
    let missing = dir.path().join("absent.yaml");
    assert!(matches!(load_templates(&missing), Err(TemplateLoadError::Config(_))));
    fs::write(&path, "templates:\n  - name: \"\"\n")?;
    assert!(matches!(load_templates(&path), Err(TemplateLoadError::Invalid(TemplateError::EmptyName))));
    Ok(())
}
