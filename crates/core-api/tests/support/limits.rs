use core_api::model::{ApiState, Limits};
use std::sync::Arc;


pub fn with_limits(state: ApiState, adjust: impl FnOnce(&mut Limits)) -> ApiState {
    let mut limits = *state.limits.load_full();
    adjust(&mut limits);
    state.limits.store(Arc::new(limits));
    state
}
