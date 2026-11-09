use crate::model::{Admission, Bucket, PageSettings, PageState};
use crate::types::{NowFn, SharedSettings};
use arc_swap::ArcSwapOption;
use lru::LruCache;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};


pub const MILLI: u64 = 1000;


pub const IPV6_HOST_BITS: u32 = 64;


/// The key of a source: IPv4 as is, IPv4-mapped IPv6 as IPv4, other IPv6 folded to its /64.
pub fn source_key(source: IpAddr) -> IpAddr {
    match source.to_canonical() {
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from((u128::from(address) >> IPV6_HOST_BITS) << IPV6_HOST_BITS)),
        other => other,
    }
}


pub fn system_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}


pub fn capacity_of(max_sources: usize) -> NonZeroUsize {
    NonZeroUsize::new(max_sources).unwrap_or(NonZeroUsize::MIN)
}


pub fn new_state(tenant: String, settings: SharedSettings, now: Box<NowFn>) -> PageState {
    let capacity = capacity_of(settings.load().max_sources);
    PageState {
        tenant,
        snapshot: ArcSwapOption::empty(),
        settings,
        buckets: Mutex::new(LruCache::new(capacity)),
        now,
        active: Arc::default(),
        sources: Arc::default(),
    }
}


/// Tops the bucket up for the time elapsed, never above the burst.
pub fn refill(bucket: &mut Bucket, now: u64, settings: &PageSettings) {
    let elapsed = now.saturating_sub(bucket.last_millis);
    let burst = u64::from(settings.burst) * MILLI;
    bucket.tokens_milli = bucket
        .tokens_milli
        .saturating_add(elapsed.saturating_mul(u64::from(settings.rate_per_second)))
        .min(burst);
    bucket.last_millis = now;
}


/// Takes one token from the source's bucket; the table never holds more than `max_sources` sources, the least recently seen leaves first.
pub fn admit(state: &PageState, source: IpAddr, settings: &PageSettings) -> Admission {
    let now = (state.now)();
    let burst = u64::from(settings.burst) * MILLI;
    let wanted = capacity_of(settings.max_sources);
    let mut table = state.buckets.lock().unwrap_or_else(PoisonError::into_inner);
    if table.cap() != wanted {
        table.resize(wanted);
    }
    let bucket = table.get_or_insert_mut(source_key(source), || Bucket {
        tokens_milli: burst,
        last_millis: now,
    });
    refill(bucket, now, settings);
    if bucket.tokens_milli >= MILLI {
        bucket.tokens_milli -= MILLI;
        Admission::Allowed
    } else {
        let missing = MILLI - bucket.tokens_milli;
        let wait_millis = missing.div_ceil(u64::from(settings.rate_per_second).max(1));
        Admission::Limited {
            retry_after_seconds: wait_millis.div_ceil(MILLI).max(1),
        }
    }
}
