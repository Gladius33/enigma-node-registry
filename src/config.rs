#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryConfig {
    pub bind_addr: String,
    pub presence_ttl_secs: u64,
    pub purge_interval_secs: u64,
    pub request_timeout_ms: u64,
    pub max_nodes: usize,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        RegistryConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            presence_ttl_secs: 300,
            purge_interval_secs: 60,
            request_timeout_ms: 3000,
            max_nodes: 2048,
        }
    }
}
