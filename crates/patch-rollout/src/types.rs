use agent_command::model::KeyClass;
use agent_command::types::BoxError;


/// The injected sequence counter: given an agent id and a key class it returns the next number of that agent and class, or the store failure.
pub type SequenceFn<'counter> = dyn FnMut(&str, KeyClass) -> Result<u64, BoxError> + 'counter;
