pub const MAX_FILE_BYTES: u64 = 1_048_576;


pub const MAX_ROUTES: usize = 1_000;


pub const MAX_HOSTS: usize = 16;


pub const MAX_PATHS: usize = 16;


pub const MAX_BACKENDS: usize = 16;


pub const MAX_HOST_BYTES: usize = 253;


pub const MAX_LABEL_BYTES: usize = 63;


pub const MAX_PATH_BYTES: usize = 256;


pub const MAX_PORT_DIGITS: usize = 5;


pub const MAX_INTERVAL_SECONDS: u64 = 3_600;


pub const DEFAULT_INTERVAL_SECONDS: u64 = 10;


pub const DEFAULT_HEALTH_PATH: &str = "/";


pub const LISTEN_ADDRESS: &str = ":8080";


pub const SERVER_NAME: &str = "main";


pub const PASSIVE_FAIL_SECONDS: u64 = 30;


pub const PASSIVE_MAX_FAILS: u32 = 3;


pub const FILE_LABEL: &str = "routes";


pub const ADMIN_PORT: u16 = 2019;


pub const DOUBLE_SLASH: &str = "//";


pub const NOT_FOUND: u16 = 404;


pub const STATIC_RESPONSE: &str = "static_response";
