use agent_command::model::KeyClass;


/// The injected per-class sequence counter: each call returns the next number of the class.
pub type SequenceFn<'counter> = dyn FnMut(KeyClass) -> u64 + 'counter;
