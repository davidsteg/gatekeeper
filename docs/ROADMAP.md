# Roadmap / known gaps

Project documentation of what is and isn't built. See
[REQUIREMENTS.md](../REQUIREMENTS.md) for the full specification behind each
item.

## Implemented

- Two-tier config (Tier 1 immutable / Tier 2 runtime-mutable)
- `docker` and `local` executors
- `http` executor — SSRF-safe, no redirects followed, credential-as-header
  injection, response size/field capping, external-data marking (`execute_http.py`)
- `truenas` executor — JSON-RPC 2.0 over WebSocket, RPC-method whitelist
  (`execute_truenas.py`)
- Credential store — write-only, encrypted at rest (`credentials.py`)
- Presets — starter toolkit YAML + tools + logo for 13 services, reachable
  from `/ui/tools/presets` (`presets.py`)
- `write_external` category — distinct rate-limit bucket, agent-facing
  "cannot be undone" warning, requires an explicit grant
- Operations console (`/ui`) — no JavaScript, CSP-locked, server-rendered SVG

## Not implemented (by design or not yet)

- **OAuth2** — the `http` executor supports static credentials only
  (bearer / API-key header / basic — FR-8.11). Services that require an
  authorization-code flow (most Google Workspace APIs: Calendar, Gmail,
  Drive, …) are out of scope for the `google_api` preset. Would need a
  separate subsystem (callback handling, token refresh/storage) — not
  justified until a concrete service requires it.
- **`ssh` executor** — optional per REQUIREMENTS.md §17, not built. The
  `truenas` executor covers the case it was mainly proposed for (`zpool
  status`, dataset management); it remains relevant only for host
  diagnostics with no API equivalent (`ps aux`, `top`).
- **TrueNAS SCRAM-SHA-512 mutual auth** — API-key auth
  (`auth.login_with_api_key`) is implemented and is the baseline; SCRAM is
  TrueNAS 26's preferred alternative and is a follow-up, not a blocker.
- **Persistent/pooled TrueNAS WebSocket connections** — each call currently
  opens its own connection, authenticates, sends one request, and closes.
  Simpler and correct for infrequent management calls; a pooled/reconnecting
  connection manager is a valid later optimization that would not change the
  tool definition contract (method + params).
- **Multi-cluster** — designed for it, not tested yet.
- **API versioning** — MCP is the only interface; no separate HTTP API for
  tools.
