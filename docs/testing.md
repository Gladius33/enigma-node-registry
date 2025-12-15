# Testing

Integration tests start the server in-process on a random localhost port using `tokio::test`. HTTP interactions use `reqwest` to exercise full JSON handling and status codes.

Presence TTL behavior is validated by configuring small TTL and purge intervals, issuing announcements, and invoking the purge helper to confirm removal.

Node sync and registration flows validate validation rules, conflict detection, and deduplication against the in-memory store.
