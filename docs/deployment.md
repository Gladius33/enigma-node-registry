# Deployment

- Compile with `--features "http,tls,persistence"` and configure PEM cert/key paths (and an optional client CA when the `mtls` feature is enabled). HTTP-only mode is for local development.
- Expose only the registry port; prefer binding to `0.0.0.0:8443` with rustls enabled.
- Keep sled data on encrypted, fast storage and monitor disk space. Presence TTL and node caps bound memory growth.
- Use systemd or another supervisor to manage lifecycle and ensure graceful shutdown on `SIGINT`.
