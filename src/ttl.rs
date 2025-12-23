use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;
use tokio::time::{Duration, Interval};

use crate::config::PresenceConfig;
use crate::error::RegistryResult;
use crate::store::Store;

pub async fn purge_expired_presences(
    store: &Store,
    now_ms: u64,
    ttl_secs: u64,
) -> RegistryResult<usize> {
    store.purge_presences(now_ms, ttl_secs).await
}

pub async fn run_purger(
    store: Arc<Store>,
    presence_cfg: PresenceConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut ticker = build_interval(presence_cfg.gc_interval_seconds);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now_ms = current_time_ms();
                let _ = purge_expired_presences(&store, now_ms, presence_cfg.ttl_seconds).await;
            }
            _ = &mut shutdown_rx => {
                break;
            }
        }
    }
}

fn build_interval(purge_interval_secs: u64) -> Interval {
    let interval_secs = purge_interval_secs.max(1);
    tokio::time::interval(Duration::from_secs(interval_secs))
}

pub fn current_time_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}
