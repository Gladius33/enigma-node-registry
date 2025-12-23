# Design

The registry only handles directory and presence concerns. Identities are exchanged inside encrypted envelopes keyed by rotating X25519 keys and a server-side pepper to resist scraping and replay. Plain identities are never returned on the wire.

## Security controls
- TLS via rustls for production, with optional mTLS when compiled with the `mtls` feature and configured with a client CA.
- Per-IP rate limiting with endpoint-specific buckets and optional proof-of-work on `resolve` and `check_user`.
- Blind indexes derived from the pepper and handle keep the persistence layer hardened against offline enumeration.

## Storage and TTL
The `persistence` feature enables sled-backed storage; otherwise a volatile in-memory store is used. Presences are purged on an interval defined in config to enforce a bounded TTL.

## Node sync
Sync merges new identities without overwriting existing ones and is guarded by `allow_sync` so operators can disable it unless explicitly trusted.
