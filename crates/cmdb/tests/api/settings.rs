use crate::fixture::fixture;
use crate::types::TestResult;
use alerts::settings::open_pg_engine_as;
use cmdb::backend::ACTOR;
use core_api::server::new_listener;
use core_config::reload::{reload, ReloadOutcome};
use std::fs;


const PG_TEXT: &str = "host: 127.0.0.1\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


const OTHER_HOST: &str = "host: 127.0.0.2\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


#[test]
fn the_audit_actor_of_a_settings_reload_is_cmdb() -> TestResult {
    let fx = fixture()?;
    let module = fx._dir.path().join("cmdb.yaml");
    let pg = fx._dir.path().join("pg.yaml");
    let audit = fx._dir.path().join("audit.log");
    fs::write(
        &module,
        format!("name: cmdb\nversion: \"1\"\ntenant: acme\nsettings:\n  pg_settings: {}\n", pg.display()),
    )?;
    fs::write(&pg, PG_TEXT)?;
    let listener = new_listener();
    listener.state.get_or_init(|| fx.state.clone());
    let (engine, _pg_file) = open_pg_engine_as(&module, listener, ACTOR)?;
    let before = fs::read_to_string(&audit)?;
    fs::write(&pg, OTHER_HOST)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let after = fs::read_to_string(&audit)?;
    let added = after.get(before.len()..).ok_or("audit shrank")?;
    assert!(added.contains("\"cmdb\""), "{added}");
    assert!(!added.contains("\"alerts\""), "{added}");
    Ok(())
}
