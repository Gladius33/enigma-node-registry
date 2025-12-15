use super::{sample_identity, shutdown_server, start_server_with};
use crate::RegistryConfig;
use enigma_node_types::{NodeInfo, NodesPayload};

#[tokio::test]
async fn rejects_invalid_inputs() {
    let server = start_server_with(RegistryConfig::default(), Vec::new()).await;
    let client = reqwest::Client::new();
    let bad_resolve = client
        .get(format!("{}/resolve/not-hex", server.base_url))
        .send()
        .await
        .expect("bad resolve");
    assert_eq!(bad_resolve.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_register = client
        .post(format!("{}/register", server.base_url))
        .json(&serde_json::json!({
            "identity": sample_identity("eve"),
            "extra": "nope"
        }))
        .send()
        .await
        .expect("invalid register");
    assert_eq!(invalid_register.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_nodes = client
        .post(format!("{}/nodes", server.base_url))
        .json(&NodesPayload {
            nodes: vec![NodeInfo {
                base_url: "ftp://invalid.test".to_string(),
            }],
        })
        .send()
        .await
        .expect("invalid nodes");
    assert_eq!(invalid_nodes.status(), reqwest::StatusCode::BAD_REQUEST);
    shutdown_server(server).await;
}
