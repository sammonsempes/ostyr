pub const MAX_POLICY_BYTES: u64 = 1_048_576;


pub const MAX_RULES: usize = 4096;


pub const MAX_INTERFACES: usize = 256;


pub const CLASS_DIGITS: usize = 2;


pub const ID_DIGITS: usize = 4;


pub const MAX_SERIAL_CHARS: usize = 126;


pub const MAX_OWNER_CHARS: usize = 64;


pub const MAX_REASON_CHARS: usize = 200;


pub const STORAGE_CLASS: &str = "08";


pub const MAX_EXTENSIONS: usize = 4096;


pub const CHROMIUM_ID_CHARS: usize = 32;


pub const FIREFOX_GUID_CHARS: usize = 38;


pub const FIREFOX_GUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];


pub const FIREFOX_LOCAL_MAX: usize = 64;


pub const FIREFOX_DOMAIN_MAX: usize = 190;


pub const MAX_UPDATE_URL_BYTES: usize = 2048;


pub const HTTPS_PREFIX: &str = "https://";


pub const RESTRICTIONS_KEY: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";


pub const LAYERED_VALUE: &str = "AllowDenyLayered";


pub const DEFAULT_BLOCK_VALUE: &str = "DenyRemovableDevices";


pub const DENY_DEVICE_IDS: &str = "DenyDeviceIDs";


pub const DENY_RETROACTIVE_VALUE: &str = "DenyDeviceIDsRetroactive";


pub const ALLOW_DEVICE_IDS: &str = "AllowDeviceIDs";


pub const ALLOW_INSTANCE_IDS: &str = "AllowInstanceIDs";


pub const ENABLED: &str = "1";
