use core_pg::scope::TenantScope;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdSubtype {
    Mac,
    Ip,
    IfName,
    IfAlias,
    Local,
    Chassis,
    Port,
}


/// A chassis or port identifier with its subtype; MAC text is lowercase colon form, IP text is canonical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NeighbourId {
    pub subtype: IdSubtype,
    pub value: String,
}


/// One neighbour seen on one local port at `seen` (unix seconds); the remote name is a display field only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub local_host: String,
    pub local_port: String,
    pub remote_chassis: NeighbourId,
    pub remote_port: NeighbourId,
    pub remote_name: Option<String>,
    pub seen: i64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Unparsable,
    BadField,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    pub unparsable: usize,
    pub bad_field: usize,
    pub dropped_display: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub observations: Vec<Observation>,
    pub skipped: Skipped,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub tenant: TenantScope,
    pub local_host: String,
    pub local_port: String,
    pub remote_chassis: NeighbourId,
    pub remote_port: NeighbourId,
    pub remote_name: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merged {
    pub links: Vec<Link>,
    pub refused_new: usize,
}
