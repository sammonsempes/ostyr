pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_ROUTES: usize = 1_000;


pub const MAX_RENDERED_UPSTREAMS: usize = 2_000;


pub const MAX_RENDERED_BYTES: usize = 3_145_728;


pub const CATCH_ALL_UPSTREAMS: usize = 1;


pub const ROUTE_INDENT_BYTES: usize = 12;


pub const MAX_JSON_BYTES: usize = 4_194_304;


pub const MAX_HOSTS: usize = 16;


pub const MAX_PATHS: usize = 16;


pub const MAX_BACKENDS: usize = 16;


pub const MAX_HOST_BYTES: usize = 253;


pub const MAX_LABEL_BYTES: usize = 63;


pub const MAX_PATH_BYTES: usize = 256;


pub const MAX_PORT_DIGITS: usize = 5;


pub const MIN_INTERVAL_SECONDS: u64 = 10;


pub const MAX_INTERVAL_SECONDS: u64 = 3_600;


pub const DEFAULT_INTERVAL_SECONDS: u64 = 10;


pub const DEFAULT_HEALTH_PATH: &str = "/";


pub const LISTEN_ADDRESS: &str = ":8080";


pub const SERVER_NAME: &str = "main";


pub const PASSIVE_FAIL_SECONDS: u64 = 30;


pub const PASSIVE_MAX_FAILS: u32 = 3;


pub const FILE_LABEL: &str = "routes";


pub const ADMIN_PORT: u16 = 2019;


pub const LISTEN_PORT: u16 = 8080;


pub const LOOP_DETECTED: u16 = 508;


pub const PROXIED_HEADER: &str = "X-Ostyr-Proxied";


pub const PROXIED_VALUE: &str = "1";


pub const DOUBLE_SLASH: &str = "//";


pub const NOT_FOUND: u16 = 404;


pub const STATIC_RESPONSE: &str = "static_response";


pub const ROUTE_SEPARATOR_BYTES: usize = 2;


pub const TLS_LISTEN_ADDRESS: &str = ":443";


pub const PROTOCOL_MIN: &str = "tls1.2";


pub const MAX_HSTS_SECONDS: u64 = 63_072_000;


pub const DEFAULT_HSTS_SECONDS: u64 = 31_536_000;


pub const HSTS_HEADER: &str = "Strict-Transport-Security";


pub const MAX_DIRECTORY_BYTES: usize = 2_048;


pub const MAX_EMAIL_BYTES: usize = 254;


pub const MAX_LOCAL_BYTES: usize = 64;


pub const MAX_CA_ROOT_BYTES: u64 = 65_536;


pub const CA_ROOT_LABEL: &str = "ca_root_file";


pub const HTTPS_PREFIX: &str = "https://";


pub const ACME_MODULE: &str = "acme";


pub const INTERNAL_MODULE: &str = "internal";


pub const SUBJECT_BYTES: usize = 18;


pub const CA_ROOT_PREFIX: &str = "ca-root-";


pub const CA_ROOT_SUFFIX: &str = ".pem";


pub const TEMP_PREFIX: &str = ".ca-root-";


pub const TEMP_SUFFIX: &str = ".tmp";


pub const CA_FILE_MODE: u32 = 0o644;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const PEM_LINE_CHARS: usize = 64;


pub const PEM_DASHES: &str = "----";


pub const PEM_BEGIN: &str = "-----BEGIN ";


pub const PEM_CERTIFICATE_BEGIN: &str = "-----BEGIN CERTIFICATE-----";


pub const PEM_CERTIFICATE_END: &str = "-----END CERTIFICATE-----";


pub const MIN_DEADLINE_SECONDS: u64 = 1;


pub const MAX_DEADLINE_SECONDS: u64 = 120;


pub const DEFAULT_DEADLINE_SECONDS: u64 = 30;


pub const DEFAULT_CADDY_PROGRAM: &str = "/usr/bin/caddy";


pub const DEFAULT_ADMIN_SOCKET: &str = "/run/ostyr-waf/caddy-admin.sock";


pub const ADMIN_LISTEN_PREFIX: &str = "unix/";


pub const ROUTES_STATE_KEY: &str = "waf.config";


pub const REFUSED_STATE_KEY: &str = "waf.refused";


pub const MAX_REFUSED_LISTED: usize = 32;


pub const FINAL_NAME: &str = "caddy.json";


pub const STAGE_PREFIX: &str = ".apply-";


pub const STAGE_SUFFIX: &str = ".json";


pub const STAGE_MODE: u32 = 0o600;


pub const VALIDATE_STEP: &str = "validate";


pub const RELOAD_STEP: &str = "reload";


pub const APPLY_SECTION: &str = "waf.caddy";


pub const SETTINGS_LABEL: &str = "waf apply settings";


pub const ID_PREFIX: &str = "ostyr-";


pub const ID_HEX_CHARS: usize = 32;


pub const STATUS_PREFIX_BYTES: usize = 12;


pub const STATUS_DIGITS_START: usize = 9;


pub const STATUS_OK: u16 = 200;


pub const MIN_REMAINING_MILLISECONDS: u64 = 1;


pub const EPOCH_STATE_KEY: &str = "waf.epoch";


pub const DEADLINE_STATE_KEY: &str = "waf.deadline_seconds";


pub const PROGRAM_STATE_KEY: &str = "waf.caddy_program";


pub const LATE_PARAMETER: &str = "late";


pub const RESULT_PARAMETER: &str = "result";


pub const APPLIED_RESULT: &str = "applied";


pub const START_DIFF: &str = "initial configuration";


pub const UNTRUSTED_ADMIN: &str = "the admin socket directory must be absolute, owned by the running user or root, and closed to group and others";
