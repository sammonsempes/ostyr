use dns_rpz::policy::{
    default_expire, default_max_records, default_negative_ttl, default_refresh, default_retry, default_tlp_allowed, default_ttl, Actions, Allowlist,
    Policy, Soa, Unbound,
};


pub const SAMPLE_MIN_CONFIDENCE: u8 = 50;


pub fn sample_policy() -> Policy {
    Policy {
        zone: "rpz.example.org".to_owned(),
        soa: Soa {
            mname: "ns1.example.org".to_owned(),
            rname: "hostmaster.example.org".to_owned(),
            refresh: default_refresh(),
            retry: default_retry(),
            expire: default_expire(),
            minimum: default_negative_ttl(),
        },
        ns: vec!["ns1.example.org".to_owned()],
        ttl: default_ttl(),
        min_confidence: SAMPLE_MIN_CONFIDENCE,
        tlp_allowed: default_tlp_allowed(),
        wildcard: true,
        max_records: default_max_records(),
        allowlist: Allowlist::default(),
        actions: Actions::default(),
        unbound: Unbound::default(),
    }
}
