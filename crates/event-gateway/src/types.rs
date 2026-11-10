use std::path::Path;


/// The settings a NATS connection is built from: address, files and user, then the three timings.
pub type ConnectionFields<'a> = (
    (&'a str, bool, Option<&'a Path>, Option<&'a Path>, Option<&'a str>, Option<&'a Path>),
    (u64, u64, u64),
);
