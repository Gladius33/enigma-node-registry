# API

All endpoints use hashed `UserId` values encoded as lowercase hex. Payload schemas come from `enigma-node-types` and reject unknown fields.

## POST /register
- Body: `RegisterRequest` containing `identity`.
- Responses: `200` with `RegisterResponse { ok: true }` on success, `409` if user already registered, `400` on validation error.

## GET /resolve/{user_id_hex}
- Returns `ResolveResponse { identity: Option<PublicIdentity> }` with status `200`. Absence is represented by `None` to reduce probing.

## GET /check_user/{user_id_hex}
- Returns `CheckUserResponse { exists: bool }` with status `200`.

## POST /announce
- Body: `Presence`.
- Returns `200` with `{ "ok": true }` after validation and upsert.

## POST /sync
- Body: `SyncRequest`.
- Returns `SyncResponse { merged: u64 }` counting identities inserted.

## GET /nodes
- Returns `NodesPayload { nodes: Vec<NodeInfo> }`.

## POST /nodes
- Body: `NodesPayload`.
- Returns `{ "merged": u64 }` after deduplication and max-size enforcement.
