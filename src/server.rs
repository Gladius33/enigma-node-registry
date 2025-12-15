use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use enigma_node_types::NodeInfo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower_http::timeout::TimeoutLayer;

use crate::config::RegistryConfig;
use crate::error::{EnigmaNodeRegistryError, Result};
use crate::routes::{build_router, AppState};
use crate::store::Store;
use crate::ttl;

pub struct RunningServer {
    pub base_url: String,
    pub shutdown: oneshot::Sender<()>,
    pub handle: JoinHandle<Result<()>>,
    #[cfg(test)]
    pub store: Arc<Store>,
}

pub async fn start(cfg: RegistryConfig, initial_nodes: Vec<NodeInfo>) -> Result<RunningServer> {
    let store = Arc::new(Store::new(cfg.max_nodes));
    store.add_nodes(initial_nodes).await?;
    let state = AppState {
        store: store.clone(),
    };
    let router = build_router(state);
    let router = apply_timeout(router, cfg.request_timeout_ms);
    let addr: SocketAddr = cfg
        .bind_addr
        .parse()
        .map_err(|_| EnigmaNodeRegistryError::InvalidInput("bind_addr"))?;
    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    let base_url = format!("http://{}", bound_addr);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (purger_tx, purger_rx) = oneshot::channel();
    let purger_cfg = cfg.clone();
    let purger_store = store.clone();
    let purger_task = tokio::spawn(async move {
        ttl::run_purger(purger_store, purger_cfg, purger_rx).await;
    });
    let server = axum::serve(listener, router.into_make_service()).with_graceful_shutdown(async {
        let _ = shutdown_rx.await;
        let _ = purger_tx.send(());
    });
    let handle = tokio::spawn(async move {
        let result = server.await;
        let _ = purger_task.await;
        match result {
            Ok(_) => Ok(()),
            Err(_) => Err(EnigmaNodeRegistryError::Transport),
        }
    });
    Ok(RunningServer {
        base_url,
        shutdown: shutdown_tx,
        handle,
        #[cfg(test)]
        store,
    })
}

fn apply_timeout(router: Router, request_timeout_ms: u64) -> Router {
    if request_timeout_ms == 0 {
        return router;
    }
    let timeout = TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_millis(request_timeout_ms),
    );
    router.layer(timeout)
}
