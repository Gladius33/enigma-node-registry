# API

Inputs reject unknown fields and return structured JSON errors `{ "error": { "code": "...", "message": "...", "details": { ... } } }`. Handles are 32-byte hex `UserId` values; identities are only returned inside encrypted envelopes.

## Endpoints
- `POST /register` — `{ handle, envelope }`, where `envelope` is an XChaCha20-Poly1305 payload encrypted with the server envelope key (kid + sender pubkey + nonce + ciphertext). `200 { ok: true }` or `409` on conflict.
- `POST /resolve` — `{ handle, requester_ephemeral_pubkey_hex }`, returns `{ handle, envelope }` encrypted back to the requester using the active envelope key. Rate limited and can require PoW.
- `GET /check_user/{handle}` — `{ exists }`, heavily rate limited and PoW-aware to reduce enumeration.
- `POST /announce` — Presence heartbeat; stored with TTL and purged by GC.
- `POST /sync` — Merge identities when `allow_sync = true`.
- `GET /nodes` / `POST /nodes` — List or add nodes with deduplication and max count enforcement.
- `GET /envelope_pubkey` and `GET /envelope_pubkeys` — Advertise current and historical envelope public keys with kid and optional expiry.
- `GET /pow/challenge` — Issue PoW challenges when the `pow` feature is enabled and `[pow].enabled = true`.

## Rate limiting and proof-of-work
- Per-IP token buckets with global and endpoint-specific limits. Exceeding a limit returns `429` with `RATE_LIMITED`.
- Optional PoW: the server issues `{ challenge, difficulty, expires_ms }` and expects header `x-enigma-pow: {challenge}:{solution}` on `/resolve` and `/check_user` when enabled.

## TLS
- TLS is served with rustls when `mode = "tls"` and the `tls` feature is compiled. `client_ca_pem_path` and the `mtls` feature enforce client certificate validation.
