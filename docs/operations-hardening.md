# Operations Hardening Guide

This checklist is for production deployments of A2A-SDL (`a2acrpt`).

## Baseline

1. Run with `--deployment-mode prod`.
2. Provide TLS listener cert/key (`--tls-cert-file`, `--tls-key-file`).
3. Enable durable replay storage (`--replay-db-file` or `--replay-redis-url`).
4. Load trusted signing and decrypt key maps.
5. Keep admin endpoints authenticated (`--admin-token`) when enabled.

## Identity and Tenant Controls

1. Require OIDC identities for inbound traffic:
   - `--oidc-required --oidc-jwks-file <jwks.json>`
2. Pin issuer/audience where available:
   - `--oidc-issuer ... --oidc-audience ...`
3. Enforce tenant boundaries:
   - `--tenant-required`
   - `--tenant-allow <tenant-id>` (repeatable)
   - `--agent-tenant-map-file <agent_tenant_map.json>`

## Observability

1. Expose admin endpoints only behind auth and trusted networks.
2. Scrape Prometheus text metrics at `/metrics`.
3. Use `/metrics.json` for machine-readable integration checks.
4. Enable periodic JSONL export for shipping to centralized collectors:
   - `--metrics-export-file /var/log/a2a/metrics.jsonl`
   - `--metrics-export-interval-s 15`

## Durability and Recovery

1. Use SQLite or Redis replay stores for restart safety.
2. For workflow orchestration with resume support, set:
   - `a2a workflow --state-db-file ...`
3. Workflow/replay SQLite files are created with restrictive permissions when possible.
4. Back up key material and durable stores according to your RPO/RTO.

## Interoperability

1. Generate canonical vectors before integration testing:

```bash
a2a vectors --out-dir docs/interop-vectors --verify
```

2. Share generated vectors with external implementers to validate wire compatibility.

