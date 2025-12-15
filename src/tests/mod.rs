use std::time::{SystemTime, UNIX_EPOCH};

use enigma_node_types::{NodeInfo, Presence, PublicIdentity, UserId};

use crate::{start, RegistryConfig, RunningServer};

mod announce_ttl_tests;
mod negative_tests;
mod register_resolve_tests;
mod sync_nodes_tests;

pub(super) fn sample_identity(username: &str) -> PublicIdentity {
    let user_id = UserId::from_username(username).expect("user id");
    PublicIdentity {
        user_id,
        username_hint: Some(username.to_string()),
        signing_public_key: vec![1, 2, 3],
        encryption_public_key: vec![4, 5, 6],
        signature: vec![7, 8, 9],
        created_at_ms: 1,
    }
}

pub(super) fn sample_presence(user_id: UserId, ts_ms: u64) -> Presence {
    Presence {
        user_id,
        addr: "127.0.0.1:9000".to_string(),
        ts_ms,
    }
}

pub(super) fn now_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => match u64::try_from(duration.as_millis()) {
            Ok(ms) => ms,
            Err(_) => u64::MAX,
        },
        Err(_) => 0,
    }
}

pub(super) async fn start_server_with(cfg: RegistryConfig, nodes: Vec<NodeInfo>) -> RunningServer {
    start(cfg, nodes).await.expect("server start")
}

pub(super) async fn shutdown_server(server: RunningServer) {
    let _ = server.shutdown.send(());
    let _ = server.handle.await;
}
