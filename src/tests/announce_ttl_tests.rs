use super::{now_ms, sample_identity, sample_presence, shutdown_server, start_server_with};
use crate::{ttl, RegistryConfig};

#[tokio::test]
async fn announce_and_purge_presence() {
    let mut cfg = RegistryConfig::default();
    cfg.presence_ttl_secs = 1;
    cfg.purge_interval_secs = 1;
    let server = start_server_with(cfg.clone(), Vec::new()).await;
    let store = server.store.clone();
    let client = reqwest::Client::new();
    let identity = sample_identity("bob");
    let ts = now_ms();
    let presence = sample_presence(identity.user_id, ts);
    let announce_resp = client
        .post(format!("{}/announce", server.base_url))
        .json(&presence)
        .send()
        .await
        .expect("announce response");
    assert_eq!(announce_resp.status(), reqwest::StatusCode::OK);
    assert!(store.presence_exists(&identity.user_id).await);
    let removed =
        ttl::purge_expired_presences(&store, ts.saturating_add(2000), cfg.presence_ttl_secs).await;
    assert_eq!(removed, 1);
    assert!(!store.presence_exists(&identity.user_id).await);
    shutdown_server(server).await;
}
