# enigma-node-registry

Enigma node registry service that handles registration, resolution, presence announcements, node sync, and user existence checks. Endpoints operate on hashed `UserId` values encoded as hex, not plaintext usernames.

## Features
- Axum HTTP server with strict JSON handling and unknown-field rejection via `enigma-node-types`.
- In-memory store with TTL-based purge of presences.
- Sync and node listing endpoints for bootstrap and discovery.
- Anti-enumeration resolve semantics: resolving returns `200` with `Option` identity instead of signaling existence via status codes.

## Quickstart
1) Run the server (defaults to an ephemeral port for testing):
```bash
cargo run --release
```
2) Register an identity using a `RegisterRequest` payload targeting `/register`.
3) Resolve via `/resolve/{user_id_hex}` to obtain `ResolveResponse` with `identity: Option<...>`.
4) Announce presence via `/announce`, then query `/check_user/{user_id_hex}` or `/nodes`.

## Deployment
Place the service behind TLS termination (Caddy/Nginx). Payloads already leverage hashed user identifiers, and plaintext usernames are never accepted.

## Testing
Integration tests spin up the server in-process on localhost using random ports and exercise HTTP endpoints with `reqwest`.
