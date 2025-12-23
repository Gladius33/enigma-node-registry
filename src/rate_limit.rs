use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::config::RateLimitConfig;
use crate::error::{RegistryError, RegistryResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RateScope {
    Global,
    Register,
    Resolve,
    CheckUser,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

impl Bucket {
    fn new(rate: f64, burst: f64) -> Self {
        Bucket {
            tokens: burst,
            last: Instant::now(),
            rate,
            burst,
        }
    }

    fn consume(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        let refill = elapsed.as_secs_f64() * self.rate;
        self.tokens = (self.tokens + refill).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct IpEntry {
    banned_until: Option<Instant>,
    buckets: HashMap<RateScope, Bucket>,
}

impl IpEntry {
    fn new(cfg: &RateLimitConfig) -> Self {
        let mut buckets = HashMap::new();
        buckets.insert(
            RateScope::Global,
            Bucket::new(cfg.per_ip_rps as f64, cfg.burst as f64),
        );
        buckets.insert(
            RateScope::Register,
            Bucket::new(cfg.endpoints.register_rps as f64, cfg.burst as f64),
        );
        buckets.insert(
            RateScope::Resolve,
            Bucket::new(cfg.endpoints.resolve_rps as f64, cfg.burst as f64),
        );
        buckets.insert(
            RateScope::CheckUser,
            Bucket::new(cfg.endpoints.check_user_rps as f64, cfg.burst as f64),
        );
        IpEntry {
            banned_until: None,
            buckets,
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    cfg: RateLimitConfig,
    inner: Arc<Mutex<HashMap<String, IpEntry>>>,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        RateLimiter {
            cfg,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check(&self, ip: &str, scope: RateScope) -> RegistryResult<()> {
        if !self.cfg.enabled {
            return Ok(());
        }
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let entry = guard
            .entry(ip.to_string())
            .or_insert_with(|| IpEntry::new(&self.cfg));
        if let Some(until) = entry.banned_until {
            if until > now {
                return Err(RegistryError::RateLimited);
            }
        }
        if !self.consume(entry, RateScope::Global, now) || !self.consume(entry, scope, now) {
            entry.banned_until = Some(now + Duration::from_secs(self.cfg.ban_seconds));
            return Err(RegistryError::RateLimited);
        }
        Ok(())
    }

    fn consume(&self, entry: &mut IpEntry, scope: RateScope, now: Instant) -> bool {
        if let Some(bucket) = entry.buckets.get_mut(&scope) {
            bucket.consume(now)
        } else {
            false
        }
    }
}
