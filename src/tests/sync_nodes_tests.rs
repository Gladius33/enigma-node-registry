use super::{sample_identity, shutdown_server, start_server_with};
use crate::RegistryConfig;
use enigma_node_types::{NodeInfo, NodesPayload, SyncRequest, SyncResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Merged {
    merged: usize,
}

#[tokio::test]
async fn sync_identities_and_nodes() {
    let mut cfg = RegistryConfig::default();
    cfg.max_nodes = 2;
    let initial_nodes = vec![NodeInfo {
        base_url: "https://node1.test".to_string(),
    }];
    let server = start_server_with(cfg, initial_nodes.clone()).await;
    let client = reqwest::Client::new();
    let id1 = sample_identity("charlie");
    let id2 = sample_identity("dana");
    let sync_resp = client
        .post(format!("{}/sync", server.base_url))
        .json(&SyncRequest {
            identities: vec![id1, id2],
        })
        .send()
        .await
        .expect("sync response");
    assert_eq!(sync_resp.status(), reqwest::StatusCode::OK);
    let sync_body: SyncResponse = sync_resp.json().await.expect("sync json");
    assert_eq!(sync_body.merged, 2);
    let nodes_resp = client
        .get(format!("{}/nodes", server.base_url))
        .send()
        .await
        .expect("nodes response");
    assert_eq!(nodes_resp.status(), reqwest::StatusCode::OK);
    let listed: NodesPayload = nodes_resp.json().await.expect("nodes json");
    assert_eq!(listed.nodes, initial_nodes);
    let add_resp = client
        .post(format!("{}/nodes", server.base_url))
        .json(&NodesPayload {
            nodes: vec![
                NodeInfo {
                    base_url: "https://node1.test".to_string(),
                },
                NodeInfo {
                    base_url: "https://node2.test".to_string(),
                },
            ],
        })
        .send()
        .await
        .expect("add nodes");
    assert_eq!(add_resp.status(), reqwest::StatusCode::OK);
    let merged: Merged = add_resp.json().await.expect("merged json");
    assert_eq!(merged.merged, 1);
    let final_nodes_resp = client
        .get(format!("{}/nodes", server.base_url))
        .send()
        .await
        .expect("final nodes");
    let final_nodes: NodesPayload = final_nodes_resp.json().await.expect("final nodes json");
    assert_eq!(final_nodes.nodes.len(), 2);
    assert!(final_nodes
        .nodes
        .iter()
        .any(|n| n.base_url == "https://node2.test"));
    shutdown_server(server).await;
}
