use crate::support::role;
use crate::types::TestResult;
use linux_fim::error::PlantError;
use linux_fim::limits::default_limits;
use linux_fim::plant::plant_role;


#[test]
fn planting_is_unsupported_off_linux() -> TestResult {
    let result = plant_role(&role("server", &[], &[]), &default_limits());
    assert!(matches!(result, Err(PlantError::Unsupported)));
    Ok(())
}
