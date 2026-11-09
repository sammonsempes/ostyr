//! Default caps and fixed constants.

pub const DEFAULT_MAX_BYTES: usize = 67_108_864;


pub const DEFAULT_MAX_COMPONENTS: usize = 100_000;


pub const DEFAULT_MAX_DEPTH: usize = 8;


pub const DEFAULT_MAX_STRING_BYTES: usize = 2048;


pub const MAX_JSON_NESTING: u32 = 256;


pub const COMPONENTS_KEY: &str = "components";


pub const UNKNOWN_KIND: &str = "unknown";


pub const NO_VERSION: &str = "";


pub const NO_NAMESPACE: &str = "";


pub const DISTRO_QUALIFIER: &str = "distro";


pub const UPSTREAM_QUALIFIER: &str = "upstream";


pub const NAME_QUOTES: usize = 2;


pub const SYFT_SECTION: &str = "syft";


pub const SYFT_STATE_KEY: &str = "syft.settings";


pub const HOME_PREFIX: &str = "syft-";


pub const STDERR_EXCERPT_BYTES: usize = 256;


pub const HELPERS_PER_RUN: usize = 2;


pub const DIRECTORY_SCHEME: &str = "dir:";


pub const OCI_SCHEME: &str = "oci-archive:";


pub const DOCKER_SCHEME: &str = "docker-archive:";


pub const SYFT_ARGUMENTS: [&str; 3] = ["scan", "-o", "cyclonedx-json"];
