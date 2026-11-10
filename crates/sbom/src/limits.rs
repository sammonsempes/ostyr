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


pub const REAP_POLL_MILLIS: u64 = 10;


pub const SBOM_SIGNING_CONTEXT: &[u8] = b"ostyr-sbom-v1\0";


pub const KEY_FILE_HEX_LENGTH: usize = 64;


pub const KEY_FILE_READ_LIMIT: u64 = 128;


pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 4_294_967_296;


pub const DEFAULT_MAX_FILE_BYTES: u64 = 2_147_483_648;


pub const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 4_294_967_296;


pub const MIN_MEMORY_BYTES: u64 = 1_073_741_824;


pub const MIN_FILE_BYTES: u64 = 1_048_576;


pub const MAX_RESOURCE_BYTES: u64 = 1_099_511_627_776;


pub const MEMORY_MARKERS: [&str; 6] = [
    "out of memory",
    "cannot allocate memory",
    "memory exhausted",
    "memory allocation of",
    "failed to reserve",
    "allocating heap arena",
];


pub const FILE_MARKERS: [&str; 2] = ["file too large", "file size limit exceeded"];


pub const DEFAULT_MAX_RUN_DISK_BYTES: u64 = 8_589_934_592;


pub const DEFAULT_MAX_RUN_ENTRIES: usize = 1_000_000;


pub const DEFAULT_DISK_POLL_MILLIS: u64 = 200;


pub const DEFAULT_PRLIMIT_BINARY: &str = "/usr/bin/prlimit";


pub const BLOCK_BYTES: u64 = 512;


pub const DRAIN_CHUNK_BYTES: u64 = 8192;
