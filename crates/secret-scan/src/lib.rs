//! Secret findings from a gitleaks JSON report, stored masked only (spec section 23).

pub mod alerting;
#[cfg(unix)]
pub mod allow;
#[cfg(unix)]
pub mod copy;
pub mod error;
pub mod mask;
pub mod model;
pub mod report;
#[cfg(unix)]
pub mod scan;
