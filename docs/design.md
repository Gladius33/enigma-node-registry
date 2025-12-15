# Design

The registry focuses solely on directory and presence concerns. It is not an offline message relay and not an SFU. Relay and media duties stay in dedicated services so that this service can remain minimal, auditable, and bandwidth-light.

## Resolve semantics
Resolution returns `200` with an optional identity instead of `404` vs `200` to limit user enumeration surface. Clients interpret the optional field to determine availability.

## Store and TTL
An in-memory store holds identities, presences, and node lists. Presences are purged on a timer based on configured TTL. Validation is enforced using `enigma-node-types` to ensure JSON strictness and consistent hashing for `UserId`.

## Node sync
Sync merges incoming identities without overwriting existing entries, supporting decentralized sharing of known peers while capping memory usage through configured maximum node count.
