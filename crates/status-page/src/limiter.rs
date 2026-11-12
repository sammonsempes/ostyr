use crate::model::{Admission, Bucket, PageSettings, PageState};
use crate::types::{NowFn, SharedSettings};
use arc_swap::ArcSwapOption;
use lru::LruCache;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};


pub const MILLI: u64 = 1000;


pub const IPV6_HOST_BITS: u32 = 64;


pub const IPV6_BITS: u32 = 128;


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
        wide_buckets: Mutex::new(LruCache::new(capacity)),
        now,
        active: Arc::default(),
        sources: Arc::default(),
        wide_sources: Arc::default(),
        proxy_malformed: AtomicUsize::new(0),
        publish_skipped: AtomicU64::new(0),
    }
}


/// The wide aggregate of an IPv6 source (the first `bits` bits); IPv4 has none, its key is already one address.
pub fn wide_key(source: IpAddr, bits: u8) -> Option<IpAddr> {
    match source.to_canonical() {
        IpAddr::V6(address) => {
            let host_bits = IPV6_BITS.saturating_sub(u32::from(bits));
            let masked = u128::from(address)
                .checked_shr(host_bits)
                .unwrap_or(0)
                .checked_shl(host_bits)
                .unwrap_or(0);
            Some(IpAddr::V6(Ipv6Addr::from(masked)))
        }
        IpAddr::V4(_) => None,
    }
}


/// Tops the bucket up for the time elapsed, never above the burst.
pub fn refill(bucket: &mut Bucket, now: u64, rate_per_second: u32, burst: u32) {
    let elapsed = now.saturating_sub(bucket.last_millis);
    let ceiling = u64::from(burst) * MILLI;
    bucket.tokens_milli = bucket
        .tokens_milli
        .saturating_add(elapsed.saturating_mul(u64::from(rate_per_second)))
        .min(ceiling);
    bucket.last_millis = now;
}


/// Takes one token from the key's bucket; the table never holds more than `max_sources` keys, the least recently seen leaves first.
pub fn take_token(table: &Mutex<LruCache<IpAddr, Bucket>>, key: IpAddr, now: u64, rate_per_second: u32, burst: u32, max_sources: usize) -> Admission {
    let wanted = capacity_of(max_sources);
    let mut guarded = table.lock().unwrap_or_else(PoisonError::into_inner);
    if guarded.cap() != wanted {
        guarded.resize(wanted);
    }
    let bucket = guarded.get_or_insert_mut(key, || Bucket {
        tokens_milli: u64::from(burst) * MILLI,
        last_millis: now,
    });
    refill(bucket, now, rate_per_second, burst);
    if bucket.tokens_milli >= MILLI {
        bucket.tokens_milli -= MILLI;
        Admission::Allowed
    } else {
        let missing = MILLI - bucket.tokens_milli;
        let wait_millis = missing.div_ceil(u64::from(rate_per_second).max(1));
        Admission::Limited {
            retry_after_seconds: wait_millis.div_ceil(MILLI).max(1),
        }
    }
}


/// Takes a token from the /64 bucket, then from the wide aggregate bucket (`wide_multiplier` times larger) of an IPv6 source.
pub fn admit(state: &PageState, source: IpAddr, settings: &PageSettings) -> Admission {
    let now = (state.now)();
    let own = take_token(
        &state.buckets,
        source_key(source),
        now,
        settings.rate_per_second,
        settings.burst,
        settings.max_sources,
    );
    match (own, wide_key(source, settings.wide_prefix_bits)) {
        (Admission::Allowed, Some(wide)) => take_token(
            &state.wide_buckets,
            wide,
            now,
            settings.rate_per_second.saturating_mul(settings.wide_multiplier),
            settings.burst.saturating_mul(settings.wide_multiplier),
            settings.max_sources,
        ),
        (other, _) => other,
    }
}
