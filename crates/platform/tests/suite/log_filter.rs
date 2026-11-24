use alerts::backend::LOG_IGNORED_CRATE;
use std::error::Error;


#[test]
fn the_ignored_log_target_is_tokio_postgres() -> Result<(), Box<dyn Error>> {
    assert_eq!(LOG_IGNORED_CRATE, "tokio_postgres");
    Ok(())
}
