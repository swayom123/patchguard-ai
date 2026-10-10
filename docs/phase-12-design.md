# Phase 12 — single-operator API security

Phase 12 protects the HTTP API for a single trusted operator. A configured bearer token protects
all API paths except `/health`, compared without a direct string equality timing leak. Production
configuration fails closed without a token of at least 32 characters and disables Swagger,
ReDoc, and the OpenAPI document. The CLI refuses a non-loopback bind unless a token is configured.

This does not add user accounts, roles, per-repository ownership, tenant isolation, rate limiting,
or TLS termination. The shared token grants identical access to every API capability. Remote
deployments must place the service behind TLS and a network firewall, store the token outside source
control, and use protected persistent storage and backups.

## Configuration

Set `PATCHGUARD_ENVIRONMENT=production` and `PATCHGUARD_API_AUTH_TOKEN` to a randomly generated
secret of at least 32 characters. Send requests with `Authorization: Bearer <token>`. Health
remains public for liveness checks; it returns no repository or finding data. API docs remain
available in development and are disabled in production. Development without a token is supported
only for loopback/local use.

## Acceptance criteria

- Production settings without a token or with a short token fail validation.
- No-token and incorrect-token requests are rejected with `401` and `WWW-Authenticate`.
- Correct bearer tokens can use protected API routes; health remains available without a token.
- Production docs and schema endpoints are not exposed.
- Non-loopback CLI binds are rejected without a token; loopback binds remain usable locally.
- The token is redacted by `SecretStr` and is never logged or returned by API responses.
- Documentation states that shared-token auth is single-operator only and requires TLS/network
  protection for remote deployment.
