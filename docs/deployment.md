# Deployment

- Run behind TLS termination (Caddy or Nginx) and proxy to the registry service. The service expects hashed `UserId` values and never accepts plaintext usernames.
- Expose only required ports; default bind is `127.0.0.1:0` for tests, but production examples use `0.0.0.0:8080` with upstream TLS.
- Monitor process memory to ensure node list caps and TTL purge keep resource usage bounded.
- Use systemd or a supervisor to manage lifecycle and handle graceful shutdown.
