pub const COLLECTOR_MODULE: &str = "collector";


pub const SNMP_TRAP_DATASET: &str = "collector.snmp_trap";


pub const NETFLOW_DATASET: &str = "collector.netflow";


pub const MAX_VARBIND_LABEL_BYTES: usize = 2048;


pub const MAX_TRAP_OID_BYTES: usize = 512;


pub const MAX_FLOW_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;


pub const MAX_FLOW_SKEW_MS: i64 = 5 * 60 * 1000;


pub const MILLIS_PER_SECOND: i64 = 1000;


pub const PROTOCOL_ICMP: u8 = 1;


pub const PROTOCOL_TCP: u8 = 6;


pub const PROTOCOL_UDP: u8 = 17;
