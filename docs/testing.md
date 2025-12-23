# Testing

- HTTP tests use `actix_web::test` to spin up the app in-process and exercise JSON validation, rate limits, and envelope roundtrips.
- Presence TTL and GC are validated by inserting presences and purging with synthetic timestamps.
- TLS tests generate self-signed certs via `rcgen` and build rustls configs under the `tls`/`mtls` feature flags.
- Proof-of-work flows are compiled in when the `pow` feature is enabled and validated through challenge/verification headers.
