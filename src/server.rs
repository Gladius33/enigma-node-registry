use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::dev::ServerHandle;
use actix_web::web;
use actix_web::{App, HttpResponse, HttpServer};
use tokio::sync::oneshot;

#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::io::BufReader;

#[cfg(feature = "tls")]
use crate::config::TlsConfig;
use crate::config::{RegistryConfig, ServerMode};
use crate::envelope::{EnvelopeCrypto, EnvelopeKeySet};
use crate::error::{ErrorBody, ErrorResponse, RegistryError, RegistryResult};
use crate::pow::PowManager as PowManagerStub;
use crate::rate_limit::RateLimiter;
use crate::routes::{configure, AppState};
use crate::store::Store;
use crate::ttl;

pub struct RunningServer {
    pub base_url: String,
    handle: ServerHandle,
    shutdown: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<RegistryResult<()>>,
    #[cfg(test)]
    pub store: Arc<Store>,
}

impl RunningServer {
    pub async fn stop(self) -> RegistryResult<()> {
        let _ = self.shutdown.send(());
        self.handle.stop(true).await;
        self.join
            .await
            .unwrap_or_else(|_| Err(RegistryError::Internal))
    }
}

pub async fn start(cfg: RegistryConfig) -> RegistryResult<RunningServer> {
    cfg.validate()?;
    let pepper = cfg.pepper_bytes();
    let store = build_store(&cfg, pepper)?;
    let store_arc = Arc::new(store);
    let keys = EnvelopeKeySet::from_config(&cfg.envelope)?;
    let crypto = EnvelopeCrypto::new(pepper);
    let rate_limiter = RateLimiter::new(cfg.rate_limit.clone());
    let pow = PowManagerStub::new(cfg.pow.clone());
    let state = AppState {
        store: store_arc.clone(),
        keys,
        crypto,
        rate_limiter,
        pow,
        presence_ttl: cfg.presence.ttl_seconds,
        allow_sync: cfg.allow_sync,
        trusted_proxies: Arc::new(cfg.trusted_proxies.clone()),
    };
    let bind_addr: SocketAddr = cfg
        .address
        .parse()
        .map_err(|_| RegistryError::Config("invalid address".to_string()))?;
    let presence_cfg = cfg.presence.clone();
    let (gc_tx, gc_rx) = oneshot::channel();
    let gc_store = store_arc.clone();
    let gc_task = tokio::spawn(async move {
        ttl::run_purger(gc_store, presence_cfg, gc_rx).await;
    });
    let (srv, base_url) = build_server(cfg, state, bind_addr).await?;
    let handle = srv.handle();
    let server_task = tokio::spawn(async move { srv.await.map_err(|_| RegistryError::Internal) });
    let join = tokio::spawn(async move {
        let res = server_task
            .await
            .unwrap_or_else(|_| Err(RegistryError::Internal));
        let _ = gc_task.await;
        res
    });
    Ok(RunningServer {
        base_url,
        handle,
        shutdown: gc_tx,
        join,
        #[cfg(test)]
        store: store_arc,
    })
}

async fn build_server(
    cfg: RegistryConfig,
    state: AppState,
    addr: SocketAddr,
) -> RegistryResult<(actix_web::dev::Server, String)> {
    let json_config = web::JsonConfig::default().error_handler(|err, _req| {
        let body = ErrorResponse {
            error: ErrorBody {
                code: "INVALID_INPUT".to_string(),
                message: err.to_string(),
                details: None,
            },
        };
        actix_web::error::InternalError::from_response(err, HttpResponse::BadRequest().json(body))
            .into()
    });
    let cfg_for_app = cfg.clone();
    let state_for_app = state.clone();
    let server_factory = move || {
        App::new()
            .app_data(json_config.clone())
            .configure(configure(&cfg_for_app, state_for_app.clone()))
    };
    match cfg.mode {
        ServerMode::Http => {
            if !cfg!(feature = "http") {
                return Err(RegistryError::FeatureDisabled("http".to_string()));
            }
            let server = HttpServer::new(server_factory)
                .bind(addr)
                .map_err(|e| RegistryError::Config(format!("failed to bind http: {}", e)))?;
            let addrs = server.addrs().to_vec();
            Ok((server.run(), format!("http://{}", addrs[0])))
        }
        ServerMode::Tls => {
            #[cfg(feature = "tls")]
            {
                let tls = cfg.tls.as_ref().ok_or_else(|| {
                    RegistryError::Config("tls configuration missing".to_string())
                })?;
                let rustls_cfg = build_rustls(tls)?;
                let server = HttpServer::new(server_factory)
                    .bind_rustls_021(addr, rustls_cfg)
                    .map_err(|e| RegistryError::Config(format!("failed to bind tls: {}", e)))?;
                let addrs = server.addrs().to_vec();
                Ok((server.run(), format!("https://{}", addrs[0])))
            }
            #[cfg(not(feature = "tls"))]
            {
                Err(RegistryError::FeatureDisabled("tls".to_string()))
            }
        }
    }
}

fn build_store(cfg: &RegistryConfig, pepper: [u8; 32]) -> RegistryResult<Store> {
    if cfg.storage.kind == "sled" {
        #[cfg(feature = "persistence")]
        {
            return Store::new_persistent(pepper, &cfg.storage.path, cfg.max_nodes);
        }
        #[cfg(not(feature = "persistence"))]
        {
            return Err(RegistryError::FeatureDisabled("persistence".to_string()));
        }
    }
    Ok(Store::new_in_memory(pepper, cfg.max_nodes))
}

#[cfg(feature = "tls")]
fn build_rustls(tls: &TlsConfig) -> RegistryResult<rustls::ServerConfig> {
    use rustls::server::AllowAnyAuthenticatedClient;
    use rustls::ServerConfig;
    let cert_chain = load_certs(&tls.cert_pem_path)?;
    let key = load_key(&tls.key_pem_path)?;
    let builder = ServerConfig::builder().with_safe_defaults();
    let config = if let Some(ca_path) = &tls.client_ca_pem_path {
        if !cfg!(feature = "mtls") {
            return Err(RegistryError::FeatureDisabled("mtls".to_string()));
        }
        let roots = load_ca(ca_path)?;
        let verifier = AllowAnyAuthenticatedClient::new(roots);
        builder
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(cert_chain, key)
            .map_err(|e| RegistryError::Config(format!("invalid certificate: {}", e)))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| RegistryError::Config(format!("invalid certificate: {}", e)))?
    };
    Ok(config)
}

#[cfg(feature = "tls")]
fn load_certs(path: &str) -> RegistryResult<Vec<rustls::Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| RegistryError::Config("failed to read certs".to_string()))?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

#[cfg(feature = "tls")]
fn load_key(path: &str) -> RegistryResult<rustls::PrivateKey> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| RegistryError::Config("failed to read private key".to_string()))?;
    if let Some(key) = keys.pop() {
        return Ok(rustls::PrivateKey(key));
    }
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| RegistryError::Config("failed to read private key".to_string()))?;
    keys.pop()
        .map(rustls::PrivateKey)
        .ok_or_else(|| RegistryError::Config("no usable private key found".to_string()))
}

#[cfg(feature = "tls")]
fn load_ca(path: &str) -> RegistryResult<rustls::RootCertStore> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| RegistryError::Config("failed to read client ca".to_string()))?;
    for cert in certs {
        roots
            .add(&rustls::Certificate(cert))
            .map_err(|_| RegistryError::Config("invalid client ca".to_string()))?;
    }
    Ok(roots)
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;
    use rand::RngCore;
    #[cfg(feature = "tls")]
    use rcgen;

    #[cfg(feature = "tls")]
    fn write_temp(content: &str, label: &str) -> String {
        let mut path = std::env::temp_dir();
        let unique = rand::thread_rng().next_u64();
        path.push(format!("enigma-registry-{label}-{unique}.pem"));
        std::fs::write(&path, content).expect("write temp");
        path.to_string_lossy().to_string()
    }

    #[cfg(feature = "tls")]
    #[actix_rt::test]
    async fn tls_server_builder_does_not_panic() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();
        let cert_path = write_temp(&cert_pem, "cert");
        let key_path = write_temp(&key_pem, "key");
        let tls_cfg = TlsConfig {
            cert_pem_path: cert_path.clone(),
            key_pem_path: key_path.clone(),
            client_ca_pem_path: None,
        };
        let cfg = build_rustls(&tls_cfg);
        std::fs::remove_file(cert_path).ok();
        std::fs::remove_file(key_path).ok();
        assert!(cfg.is_ok());
    }

    #[cfg(all(feature = "tls", feature = "mtls"))]
    #[actix_rt::test]
    async fn mtls_config_loads() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.serialize_pem().unwrap();
        let key_pem = cert.serialize_private_key_pem();
        let ca_path = write_temp(&cert_pem, "ca");
        let cert_path = write_temp(&cert_pem, "cert");
        let key_path = write_temp(&key_pem, "key");
        let tls_cfg = TlsConfig {
            cert_pem_path: cert_path.clone(),
            key_pem_path: key_path.clone(),
            client_ca_pem_path: Some(ca_path.clone()),
        };
        let cfg = build_rustls(&tls_cfg);
        std::fs::remove_file(cert_path).ok();
        std::fs::remove_file(key_path).ok();
        std::fs::remove_file(ca_path).ok();
        assert!(cfg.is_ok());
    }
}
