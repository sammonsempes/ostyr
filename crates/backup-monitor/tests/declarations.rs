use backup_monitor::declarations::{load_declarations, MAX_ENTRIES};
use backup_monitor::error::BackupError;
use core_pg::scope::tenant_of;
use std::error::Error;


const TWO: usize = 2;


fn refused(text: &str, what: &str) -> bool {
    matches!(load_declarations(text, "d.yaml"), Err(BackupError::InvalidDeclarations { what: found }) if found == what)
}


#[test]
fn a_full_file_is_loaded() -> Result<(), Box<dyn Error>> {
    let text = "tenant: acme\nhostname_from_name: true\ncritical:\n  - host: web1\n    max_age_hours: 1\n  - host: db1\n    max_age_hours: 8760\n\
                repositories:\n  - repository: repo\n    expected_min_snapshots: 3\n";
    let declarations = load_declarations(text, "d.yaml")?;
    assert_eq!(tenant_of(&declarations.tenant), "acme");
    assert!(declarations.hostname_from_name);
    assert_eq!(declarations.critical.len(), TWO);
    assert_eq!(declarations.repositories.len(), 1);
    Ok(())
}


#[test]
fn defaults_are_empty() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations("tenant: acme\n", "d.yaml")?;
    assert!(!declarations.hostname_from_name && declarations.critical.is_empty() && declarations.repositories.is_empty());
    Ok(())
}


#[test]
fn unknown_fields_and_bad_tenants_are_refused() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        load_declarations("tenant: acme\nextra: 1\n", "d.yaml"),
        Err(BackupError::Declarations(_))
    ));
    assert!(matches!(
        load_declarations("tenant: acme\ncritical:\n  - host: a\n    max_age_hours: 1\n    extra: 1\n", "d.yaml"),
        Err(BackupError::Declarations(_))
    ));
    assert!(matches!(load_declarations("tenant: -x\n", "d.yaml"), Err(BackupError::Tenant(_))));
    assert!(matches!(load_declarations("critical: []\n", "d.yaml"), Err(BackupError::Declarations(_))));
    Ok(())
}


#[test]
fn critical_hosts_are_checked() -> Result<(), Box<dyn Error>> {
    assert!(refused("tenant: a\ncritical:\n  - host: -x\n    max_age_hours: 1\n", "critical host"));
    assert!(refused("tenant: a\ncritical:\n  - host: \"\"\n    max_age_hours: 1\n", "critical host"));
    assert!(refused("tenant: a\ncritical:\n  - host: a\n    max_age_hours: 0\n", "max_age_hours"));
    assert!(refused("tenant: a\ncritical:\n  - host: a\n    max_age_hours: 8761\n", "max_age_hours"));
    assert!(refused(
        "tenant: a\ncritical:\n  - host: a\n    max_age_hours: 1\n  - host: a\n    max_age_hours: 2\n",
        "duplicate critical host"
    ));
    Ok(())
}


#[test]
fn repositories_are_checked() -> Result<(), Box<dyn Error>> {
    assert!(refused(
        "tenant: a\nrepositories:\n  - repository: -r\n    expected_min_snapshots: 1\n",
        "repository"
    ));
    assert!(refused(
        "tenant: a\nrepositories:\n  - repository: r\n    expected_min_snapshots: 0\n",
        "expected_min_snapshots"
    ));
    assert!(refused(
        "tenant: a\nrepositories:\n  - repository: r\n    expected_min_snapshots: 1000001\n",
        "expected_min_snapshots"
    ));
    assert!(refused(
        "tenant: a\nrepositories:\n  - repository: r\n    expected_min_snapshots: 1\n  - repository: r\n    expected_min_snapshots: 2\n",
        "duplicate repository"
    ));
    Ok(())
}


#[test]
fn entry_counts_are_capped_at_n_and_n_plus_one() -> Result<(), Box<dyn Error>> {
    let hosts = |count: usize| {
        (0..count).fold(String::from("tenant: a\ncritical:\n"), |text, number| {
            format!("{text}  - host: h{number}\n    max_age_hours: 1\n")
        })
    };
    assert_eq!(load_declarations(&hosts(MAX_ENTRIES), "d.yaml")?.critical.len(), MAX_ENTRIES);
    assert!(refused(&hosts(MAX_ENTRIES + 1), "entry count"));
    let repositories = (0..=MAX_ENTRIES).fold(String::from("tenant: a\nrepositories:\n"), |text, number| {
        format!("{text}  - repository: r{number}\n    expected_min_snapshots: 1\n")
    });
    assert!(refused(&repositories, "entry count"));
    Ok(())
}
