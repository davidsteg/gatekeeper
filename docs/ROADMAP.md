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
- Destinations — a `docker`/`http`/`truenas` toolkit may declare several
  named targets (e.g. two Docker hosts); tools expand at catalog-load time
  into destination-qualified, independently-grantable IDs
  (`docker.compose_up@nas1`) — REQUIREMENTS.md FR-8.3g-j (`tier1.py`,
  `catalog.py`)
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
- **API versioning** — MCP is the only interface; no separate HTTP API for
  tools.
- **Per-destination `allowed_cidrs`/`allowed_methods`/`allowed_path_prefixes`** —
  an `http` toolkit's SSRF/target restrictions (FR-8.9/8.15) are still
  toolkit-wide, shared across every destination it declares (`tier1.py`'s
  `Destination` carries only the connection target, not the toolkit's other
  boundaries — FR-4.9). Doesn't let a call to one destination reach another
  (the target itself stays fixed per destination, FR-8.3i), but the CIDR
  allowlist a single destination's SSRF check accepts is wider than
  strictly necessary when destinations sit on different subnets. Narrowing
  this per destination is a deliberate follow-up, not done here to avoid
  widening `Destination`'s scope past "where," not "what," in the same
  pass that introduced it.
- **`Toolkit`/`Destination` as a tagged union per executor** — both remain
  flat dataclasses carrying every executor's fields at once (docker/http/
  truenas), relying on convention (irrelevant fields stay `None`/default)
  rather than the type system to keep e.g. a `docker` toolkit from also
  setting `base_url`. A `Toolkit.target: DockerTarget | HttpTarget |
  TruenasTarget` redesign would make that class of mistake unrepresentable,
  but touches every executor's call sites — a larger, riskier change than
  fits alongside a feature addition; a candidate for its own pass.
