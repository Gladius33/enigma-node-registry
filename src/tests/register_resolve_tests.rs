use super::{sample_identity, shutdown_server, start_server_with};
use crate::RegistryConfig;
use enigma_node_types::{RegisterRequest, RegisterResponse, ResolveResponse};

#[tokio::test]
async fn register_and_resolve_identity() {
    let server = start_server_with(RegistryConfig::default(), Vec::new()).await;
    let client = reqwest::Client::new();
    let identity = sample_identity("alice");
    let register_url = format!("{}/register", server.base_url);
    let register_resp = client
        .post(register_url)
        .json(&RegisterRequest {
            identity: identity.clone(),
        })
        .send()
        .await
        .expect("register response");
    assert_eq!(register_resp.status(), reqwest::StatusCode::OK);
    let parsed: RegisterResponse = register_resp.json().await.expect("register json");
    assert!(parsed.ok);
    let resolve_url = format!("{}/resolve/{}", server.base_url, identity.user_id.to_hex());
    let resolve_resp = client
        .get(resolve_url)
        .send()
        .await
        .expect("resolve response");
    assert_eq!(resolve_resp.status(), reqwest::StatusCode::OK);
    let resolved: ResolveResponse = resolve_resp.json().await.expect("resolve json");
    assert_eq!(resolved.identity, Some(identity.clone()));
    let conflict = client
        .post(format!("{}/register", server.base_url))
        .json(&RegisterRequest { identity })
        .send()
        .await
        .expect("conflict response");
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
    shutdown_server(server).await;
}
