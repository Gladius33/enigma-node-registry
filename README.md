# enigma-node-registry

Registry daemon for Enigma nodes with envelope-based registration, TLS, rate limiting, proof-of-work (optional), and presence TTL/GC. All responses are structured JSON and inputs are strictly validated.

## Quickstart (HTTP, local dev)
```bash
cargo run --features http -- --config registry.toml
```
Use `storage.kind = "memory"` for local runs without sled. Endpoints listen on `address` from the config (default `0.0.0.0:8443`).

## Quickstart (TLS, production)
```bash
cargo run --release --features "http,tls,persistence" -- --config registry.toml
```
Provide PEM-encoded cert/key paths under `[tls]`. Enable `mtls` feature and set `client_ca_pem_path` to require client certificates. Persistence uses sled when the `persistence` feature is enabled and `storage.kind = "sled"`.

## Config example
```toml
address = "0.0.0.0:8443"
mode = "tls"
allow_sync = true

[rate_limit]
enabled = true
per_ip_rps = 5
burst = 10
ban_seconds = 300
[rate_limit.endpoints]
register_rps = 1
resolve_rps = 3
check_user_rps = 10

[envelope]
pepper_hex = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
keys = [{ kid_hex = "0001020304050607", x25519_private_key_hex = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", active = true }]

[tls]
cert_pem_path = "/etc/enigma/registry.cert"
key_pem_path = "/etc/enigma/registry.key"
# client_ca_pem_path = "/etc/enigma/ca.pem" # enable when mtls feature is on

[storage]
kind = "sled"
path = "./registry_db"

[presence]
ttl_seconds = 300
gc_interval_seconds = 60

[pow]
enabled = false
difficulty = 18
ttl_seconds = 120
```

## Endpoint summary
- `POST /register` — `{ handle, envelope }` encrypted to the server envelope key. Returns `{ ok }` or `409` on conflict.
- `POST /resolve` — `{ handle, requester_ephemeral_pubkey_hex }` and returns `{ handle, envelope }` encrypted to the requester using the active envelope key. Enforced rate limit and optional PoW.
- `GET /check_user/{handle}` — `{ exists }` with anti-enumeration rate limits and optional PoW.
- `POST /announce` — presence heartbeat for a device.
- `POST /sync` — merges provided identities when `allow_sync = true`.
- `GET/POST /nodes` — list or add nodes (deduped, capped).
- `GET /envelope_pubkey` and `GET /envelope_pubkeys` — advertise current and historical envelope keys.
- `GET /pow/challenge` — available when `pow` feature is compiled and enabled in config.

Errors follow `{ "error": { "code": "...", "message": "...", "details": { ... } } }`.

## Security notes
- TLS via rustls is recommended in production; HTTP is for local development only.
- Rate limits and optional PoW protect `/resolve` and `/check_user` from scraping.
- Identities are only returned inside encrypted envelopes keyed by X25519 and a peppered blind index.
- Presence entries are purged on a GC interval using the configured TTL.

## Testing
```bash
cargo test
cargo test --features tls,persistence
cargo test --features tls,mtls,persistence
cargo build --release --features tls,persistence
```
