## Unreleased

- Added TLS and optional mTLS support via rustls with PEM-configured certs and client CAs
- Introduced envelope key rotation with `/envelope_pubkey` and `/envelope_pubkeys` plus encrypted register/resolve flows
- Added sled-backed persistence behind the `persistence` feature with presence TTL/GC
- Implemented per-endpoint rate limiting, optional proof-of-work challenges, and structured JSON errors
- Added server binary with TOML config loading and updated docs/tests for new security features
