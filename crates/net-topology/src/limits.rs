pub const DEFAULT_MAX_BYTES: u64 = 4_194_304;


pub const DEFAULT_MAX_PORT_BYTES: u64 = 2_097_152;


pub const DEFAULT_MAX_HOST_READ_BYTES: u64 = 16_777_216;


pub const MAX_HOST_READ_BYTES_CEILING: u64 = 268_435_456;


pub const DEFAULT_MAX_INTERFACES: usize = 512;


pub const DEFAULT_MAX_NEIGHBOURS_PER_INTERFACE: usize = 16;


pub const DEFAULT_MAX_CAPABILITIES: usize = 16;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 256;


pub const DEFAULT_MAX_LINKS_PER_HOST: usize = 1_024;


pub const DEFAULT_MAX_LINKS_PER_PORT: usize = 16;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_port_bytes: u64,
    pub max_host_read_bytes: u64,
    pub max_interfaces: usize,
    pub max_neighbours_per_interface: usize,
    pub max_capabilities: usize,
    pub max_text_bytes: usize,
    pub max_links_per_host: usize,
    pub max_links_per_port: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_port_bytes: DEFAULT_MAX_PORT_BYTES,
            max_host_read_bytes: DEFAULT_MAX_HOST_READ_BYTES,
            max_interfaces: DEFAULT_MAX_INTERFACES,
            max_neighbours_per_interface: DEFAULT_MAX_NEIGHBOURS_PER_INTERFACE,
            max_capabilities: DEFAULT_MAX_CAPABILITIES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_links_per_host: DEFAULT_MAX_LINKS_PER_HOST,
            max_links_per_port: DEFAULT_MAX_LINKS_PER_PORT,
        }
    }
}
