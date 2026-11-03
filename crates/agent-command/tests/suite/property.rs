use crate::common::setup;
use crate::common::NOW;
use agent_command::verify::verify_command;
use proptest::prelude::*;


const MAX_RANDOM_LENGTH: usize = 512;


proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn random_bytes_never_verify_and_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..MAX_RANDOM_LENGTH)) {
        let setup = setup().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(verify_command(&setup.verifier, &bytes, NOW).is_err());
    }
}
