use siem_schema::column::{Column, ColumnType};
use siem_schema::create::render_create_table;
use siem_schema::error::SchemaError;
use siem_schema::identifier::{quote_identifier, validate_identifier};
use siem_schema::migrate::{render_migration, render_ttl_migration};
use siem_schema::schema::default_columns;
use siem_schema::ttl::{render_ttl, TierRetention, TtlSettings, MAX_RETENTION_DAYS, MAX_TIERS};


const DEFAULT_DAYS: u32 = 30;


const PREMIUM_DAYS: u32 = 90;


fn column(name: &str, column_type: ColumnType) -> Column {
    Column {
        name: name.to_string(),
        column_type,
    }
}


fn minimal() -> Vec<Column> {
    vec![
        column("@timestamp", ColumnType::Timestamp),
        column("tenant", ColumnType::LowCardinalityText),
        column("tenant_tier", ColumnType::LowCardinalityText),
        column("event.category", ColumnType::ArrayLowCardinalityText),
    ]
}


fn plain_ttl() -> TtlSettings {
    TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    }
}


fn tier(name: &str, days: u32) -> TierRetention {
    TierRetention {
        tier: name.to_string(),
        hot_days: days,
        move_after_days: None,
    }
}


#[test]
fn golden_ddl() -> Result<(), SchemaError> {
    let sql = render_create_table("events", &minimal(), &plain_ttl())?;
    let expected = "CREATE TABLE `events`
(
    `@timestamp` DateTime64(3, 'UTC'),
    `tenant` LowCardinality(String),
    `tenant_tier` LowCardinality(String),
    `event.category` Array(LowCardinality(String))
)
ENGINE = MergeTree
PARTITION BY toDate(`@timestamp`)
ORDER BY (`tenant`, `@timestamp`)
TTL toDateTime(`@timestamp`) + toIntervalDay(30)
";
    assert_eq!(sql, expected);
    Ok(())
}


#[test]
fn default_columns_render_with_arrays_and_tiers() -> Result<(), SchemaError> {
    let ttl = TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: None,
        storage_policy: None,
        cold_volume: None,
        tiers: vec![tier("premium", PREMIUM_DAYS)],
    };
    let sql = render_create_table("events", &default_columns(), &ttl)?;
    assert!(sql.contains("`event.type` Array(LowCardinality(String))"));
    assert!(sql.contains("`host.ip` Array(String)"));
    assert!(sql.contains("`process.pid` UInt32"));
    assert!(sql.contains("`source.port` UInt16"));
    assert!(sql.contains("`file.size` UInt64"));
    assert!(sql.contains("`process.executable` String"));
    assert!(sql.contains("multiIf(`tenant_tier` = 'premium', toIntervalDay(90), toIntervalDay(30))"));
    Ok(())
}


#[test]
fn create_refusals() -> Result<(), SchemaError> {
    assert!(matches!(
        render_create_table("ev;ents", &minimal(), &plain_ttl()),
        Err(SchemaError::InvalidIdentifier(_))
    ));
    let without_tenant: Vec<Column> = minimal().into_iter().filter(|item| item.name != "tenant").collect();
    assert_eq!(
        render_create_table("events", &without_tenant, &plain_ttl()),
        Err(SchemaError::MissingColumn("tenant".to_string()))
    );
    let mut duplicated = minimal();
    duplicated.push(column("tenant", ColumnType::Text));
    assert_eq!(
        render_create_table("events", &duplicated, &plain_ttl()),
        Err(SchemaError::DuplicateColumn("tenant".to_string()))
    );
    let mut hostile = minimal();
    hostile.push(column("a`b", ColumnType::Text));
    assert!(matches!(
        render_create_table("events", &hostile, &plain_ttl()),
        Err(SchemaError::InvalidIdentifier(_))
    ));
    let bad_ttl = TtlSettings {
        default_days: 0,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    };
    assert!(matches!(
        render_create_table("events", &minimal(), &bad_ttl),
        Err(SchemaError::InvalidDays(0, _))
    ));
    Ok(())
}


#[test]
fn ttl_validation() -> Result<(), SchemaError> {
    let too_long = TtlSettings {
        default_days: MAX_RETENTION_DAYS + 1,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    };
    assert_eq!(
        render_ttl(&too_long),
        Err(SchemaError::InvalidDays(MAX_RETENTION_DAYS + 1, MAX_RETENTION_DAYS))
    );
    let at_limit = TtlSettings {
        default_days: MAX_RETENTION_DAYS,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    };
    assert!(render_ttl(&at_limit).is_ok());
    let many = TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: None,
        storage_policy: None,
        cold_volume: None,
        tiers: (0..=MAX_TIERS).map(|index| tier(&format!("t{index}"), DEFAULT_DAYS)).collect(),
    };
    assert_eq!(render_ttl(&many), Err(SchemaError::TooManyTiers(MAX_TIERS + 1, MAX_TIERS)));
    let bad_name = TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: None,
        storage_policy: None,
        cold_volume: None,
        tiers: vec![tier("x' OR 1", DEFAULT_DAYS)],
    };
    assert!(matches!(render_ttl(&bad_name), Err(SchemaError::InvalidIdentifier(_))));
    let bad_days = TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: None,
        storage_policy: None,
        cold_volume: None,
        tiers: vec![tier("gold", 0)],
    };
    assert_eq!(render_ttl(&bad_days), Err(SchemaError::InvalidDays(0, MAX_RETENTION_DAYS)));
    Ok(())
}


#[test]
fn identifiers() -> Result<(), SchemaError> {
    assert_eq!(quote_identifier("@timestamp")?, "`@timestamp`");
    assert_eq!(validate_identifier("process.parent.pid_1")?, "process.parent.pid_1");
    ["", "Upper", "a b", "a`b", "a;b", "a-b", "é"]
        .iter()
        .for_each(|name| assert_eq!(validate_identifier(name), Err(SchemaError::InvalidIdentifier((*name).to_string()))));
    Ok(())
}


#[test]
fn migration_adds_columns() -> Result<(), SchemaError> {
    let old = minimal();
    let mut newer = minimal();
    newer.push(column("host.name", ColumnType::Text));
    newer.push(column("process.pid", ColumnType::UInt32));
    assert_eq!(
        render_migration("events", &old, &newer)?,
        "ALTER TABLE `events` ADD COLUMN `host.name` String, ADD COLUMN `process.pid` UInt32\n"
    );
    assert_eq!(render_migration("events", &old, &old)?, "");
    Ok(())
}


#[test]
fn migration_refusals() -> Result<(), SchemaError> {
    let old = minimal();
    let removed: Vec<Column> = minimal().into_iter().filter(|item| item.name != "tenant").collect();
    assert_eq!(
        render_migration("events", &old, &removed),
        Err(SchemaError::RemovedColumn("tenant".to_string()))
    );
    let mut retyped = minimal();
    retyped.push(column("x", ColumnType::Text));
    let mut retyped_new = minimal();
    retyped_new.push(column("x", ColumnType::UInt64));
    assert_eq!(
        render_migration("events", &retyped, &retyped_new),
        Err(SchemaError::ChangedColumn("x".to_string()))
    );
    assert!(matches!(render_migration("a b", &old, &old), Err(SchemaError::InvalidIdentifier(_))));
    let mut duplicated = minimal();
    duplicated.push(column("tenant", ColumnType::Text));
    assert!(matches!(
        render_migration("events", &duplicated, &old),
        Err(SchemaError::DuplicateColumn(_))
    ));
    assert!(matches!(
        render_migration("events", &old, &duplicated),
        Err(SchemaError::DuplicateColumn(_))
    ));
    let mut hostile = minimal();
    hostile.push(column("a`b", ColumnType::Text));
    assert!(matches!(
        render_migration("events", &old, &hostile),
        Err(SchemaError::InvalidIdentifier(_))
    ));
    Ok(())
}


const MOVE_DAYS: u32 = 7;


fn cold_ttl() -> TtlSettings {
    TtlSettings {
        default_days: DEFAULT_DAYS,
        default_move_after_days: Some(MOVE_DAYS),
        tiers: vec![TierRetention {
            tier: "premium".to_string(),
            hot_days: PREMIUM_DAYS,
            move_after_days: Some(DEFAULT_DAYS),
        }],
        storage_policy: Some("tiered".to_string()),
        cold_volume: Some("cold".to_string()),
    }
}


#[test]
fn cold_move_renders_before_delete() -> Result<(), SchemaError> {
    let expected = "toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'premium', toIntervalDay(30), toIntervalDay(7)) TO VOLUME 'cold', \
toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'premium', toIntervalDay(90), toIntervalDay(30)) DELETE";
    assert_eq!(render_ttl(&cold_ttl())?, expected);
    let sql = render_create_table("events", &minimal(), &cold_ttl())?;
    assert!(sql.ends_with(&format!("TTL {expected}\nSETTINGS storage_policy = 'tiered'\n")));
    let mut no_tiers = cold_ttl();
    no_tiers.tiers = vec![];
    assert_eq!(
        render_ttl(&no_tiers)?,
        "toDateTime(`@timestamp`) + toIntervalDay(7) TO VOLUME 'cold', toDateTime(`@timestamp`) + toIntervalDay(30) DELETE"
    );
    Ok(())
}


#[test]
fn cold_move_defaults_to_retention_when_unset() -> Result<(), SchemaError> {
    let mut only_tier = cold_ttl();
    only_tier.default_move_after_days = None;
    let sql = render_ttl(&only_tier)?;
    assert!(sql.starts_with("toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'premium', toIntervalDay(30), toIntervalDay(30)) TO VOLUME"));
    let mut tier_without_move = cold_ttl();
    tier_without_move.tiers = vec![tier("gold", PREMIUM_DAYS)];
    assert!(render_ttl(&tier_without_move)?
        .starts_with("toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'gold', toIntervalDay(90), toIntervalDay(7))"));
    Ok(())
}


#[test]
fn storage_policy_alone_only_adds_settings() -> Result<(), SchemaError> {
    let mut policy_only = plain_ttl();
    policy_only.storage_policy = Some("tiered".to_string());
    let sql = render_create_table("events", &minimal(), &policy_only)?;
    assert!(sql.ends_with("TTL toDateTime(`@timestamp`) + toIntervalDay(30)\nSETTINGS storage_policy = 'tiered'\n"));
    Ok(())
}


#[test]
fn cold_refusals() -> Result<(), SchemaError> {
    let mut late = cold_ttl();
    late.default_move_after_days = Some(DEFAULT_DAYS);
    assert_eq!(render_ttl(&late), Err(SchemaError::MoveNotBeforeRetention(DEFAULT_DAYS, DEFAULT_DAYS)));
    let mut tier_late = cold_ttl();
    tier_late.tiers = vec![TierRetention {
        tier: "premium".to_string(),
        hot_days: PREMIUM_DAYS,
        move_after_days: Some(PREMIUM_DAYS),
    }];
    assert_eq!(
        render_ttl(&tier_late),
        Err(SchemaError::MoveNotBeforeRetention(PREMIUM_DAYS, PREMIUM_DAYS))
    );
    let mut zero = cold_ttl();
    zero.default_move_after_days = Some(0);
    assert_eq!(render_ttl(&zero), Err(SchemaError::InvalidDays(0, MAX_RETENTION_DAYS)));
    let mut no_volume = cold_ttl();
    no_volume.cold_volume = None;
    assert_eq!(render_ttl(&no_volume), Err(SchemaError::MissingColdVolume));
    let mut bad_volume = cold_ttl();
    bad_volume.cold_volume = Some("c'old".to_string());
    assert!(matches!(render_ttl(&bad_volume), Err(SchemaError::InvalidIdentifier(_))));
    let mut bad_policy = cold_ttl();
    bad_policy.storage_policy = Some("a b".to_string());
    assert!(matches!(
        render_create_table("events", &minimal(), &bad_policy),
        Err(SchemaError::InvalidIdentifier(_))
    ));
    Ok(())
}


#[test]
fn ttl_migration() -> Result<(), SchemaError> {
    let mut before = plain_ttl();
    before.storage_policy = Some("tiered".to_string());
    let after = cold_ttl();
    let sql = render_ttl_migration("events", &before, &after)?;
    assert!(sql.starts_with("ALTER TABLE `events` MODIFY TTL toDateTime(`@timestamp`) + multiIf("));
    assert!(sql.ends_with(" DELETE\n"));
    assert_eq!(render_ttl_migration("events", &after, &after)?, "");
    assert_eq!(render_ttl_migration("events", &after, &before), Err(SchemaError::RemovedMove));
    assert_eq!(
        render_ttl_migration("events", &before, &plain_ttl()),
        Err(SchemaError::ChangedStoragePolicy)
    );
    assert!(matches!(
        render_ttl_migration("a b", &before, &after),
        Err(SchemaError::InvalidIdentifier(_))
    ));
    Ok(())
}
