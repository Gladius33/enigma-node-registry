use std::env;
use std::process;

use enigma_node_registry::{start, RegistryConfig};

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{}", err);
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "registry.toml".to_string());
    let cfg = RegistryConfig::load_from_path(&path)?;
    let server = start(cfg).await?;
    println!("enigma-node-registry listening on {}", server.base_url);
    tokio::signal::ctrl_c().await?;
    server.stop().await?;
    Ok(())
}
