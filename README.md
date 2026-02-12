# A2A-SDL

[![PyPI version](https://img.shields.io/pypi/v/a2acrpt.svg)](https://pypi.org/project/a2acrpt/)
[![Python versions](https://img.shields.io/pypi/pyversions/a2acrpt.svg)](https://pypi.org/project/a2acrpt/)
[![CI](https://github.com/psspssr/crpt/actions/workflows/ci.yml/badge.svg)](https://github.com/psspssr/crpt/actions/workflows/ci.yml)

A2A-SDL is a production-oriented reference implementation of a self-describing agent-to-agent protocol with strict envelope validation, deterministic encoding, and optional cryptographic security.

Published package: https://pypi.org/project/a2acrpt/ (current release: `0.2.0`)

## Project Status

- Protocol version: `v1`
- Wire specification: `docs/protocol-v1.md`
- Package name: `a2acrpt`
- Python: `>=3.11`
- Scope: secure messaging envelopes and transport bindings (HTTP/WS/IPC), not a full agent platform

## Core Capabilities

- Envelope validation with strict limits (`max_bytes`, `max_depth`, `max_array_len`, trace hop enforcement)
- Canonical JSON encoding and optional canonical CBOR
- Schema descriptors (embedded or URI) with hash verification
- Security primitives: Ed25519 signatures, X25519 + ChaCha20-Poly1305 encryption
- Replay protection backends: in-memory, SQLite, Redis
- Secure policy enforcement (`enc+sig+replay`, key trust maps, key rotation/revocation/expiry)
- Runtime compatibility and migration policy enforcement (`cap.a2a_sdl.v`, deprecation/version ranges)
- HTTP/WS/IPC transport parity with structured protocol errors
- Optional admin observability endpoints (`/healthz`, `/readyz`, `/metrics`)
- Tamper-evident audit log with optional external hash anchoring

## Protocol Spec And Conformance

- Normative wire contract: `docs/protocol-v1.md`
- Conformance runner: `a2a conformance`
- Test categories:
  - Golden vectors (valid flows)
  - Negative vectors (expected validation failures)
  - Failure mapping checks (`UNSUPPORTED_CT`, `UNSUPPORTED_ENCODING`, etc.)
  - Transport load checks (concurrent roundtrip)

Run full local conformance:

```bash
a2a conformance --transport all --mode all --format text
```

Run a targeted CI-style profile:

```bash
a2a conformance --transport http --mode secure --skip-load --format json
```

## Compatibility Matrix (CI)

Conformance is enforced in CI across:

- Python: `3.11`, `3.12`
- Transports: `http`, `ipc`, `ws`
- Modes: `dev`, `secure`

Current matrix target:

| Python | HTTP dev | HTTP secure | IPC dev | IPC secure | WS dev | WS secure |
| --- | --- | --- | --- | --- | --- | --- |
| 3.11 | yes | yes | yes | yes | yes | yes |
| 3.12 | yes | yes | yes | yes | yes | yes |

## Install

Recommended (isolated CLI install with `uv`):

```bash
uv tool install --upgrade "a2acrpt[full]"
uv tool update-shell
```

Alternatives:

```bash
pipx install "a2acrpt[full]"
pip install "a2acrpt[full]"
```

Optional extras:

- `a2acrpt[cbor]`
- `a2acrpt[schema]`
- `a2acrpt[http]`
- `a2acrpt[ws]`
- `a2acrpt[redis]`

## Quick Start

This flow does not require a repository checkout.

1. Start a local server:

```bash
a2a serve --host 127.0.0.1 --port 8080 --deployment-mode dev --allow-insecure-http
```

2. Create a minimal valid `task.v1` payload:

```bash
cat > task.json <<'JSON'
{
  "kind": "task.v1",
  "goal": "Return a short confirmation message",
  "inputs": {},
  "constraints": {
    "time_budget_s": 30,
    "compute_budget": "low",
    "safety": {}
  },
  "deliverables": [
    {"type": "text", "description": "One-line confirmation"}
  ],
  "acceptance": ["Respond with a valid A2A envelope"],
  "context": {}
}
JSON
```

3. Send the request:

```bash
a2a send \
  --url http://127.0.0.1:8080/a2a \
  --ct task.v1 \
  --payload-file task.json
```

Expected result: a response envelope (typically `state.v1` or `error.v1`) printed as JSON.

## Production Baseline

Minimum safe baseline before internet exposure:

- Use `--deployment-mode prod`
- Enforce TLS (and mTLS if required)
- Enforce `--secure-required`
- Use durable replay storage (`--replay-db-file` or `--replay-redis-url`)
- Load trusted signing/decryption keys and agent authorization maps
- Protect admin endpoints with `--admin-token`

Example hardened server profile:

```bash
a2a serve \
  --host 0.0.0.0 --port 8443 \
  --deployment-mode prod \
  --secure-required \
  --tls-cert-file /etc/a2a/tls/server.crt \
  --tls-key-file /etc/a2a/tls/server.key \
  --tls-ca-file /etc/a2a/tls/ca.crt \
  --tls-require-client-cert \
  --replay-redis-url redis://redis.internal:6379/0 \
  --trusted-signing-keys-file trusted_signing_keys.json \
  --decrypt-keys-file decrypt_keys.json \
  --agent-kid-map-file agent_kid_map.json \
  --admin-token '<strong-token>'
```

Sender-side HTTPS + mTLS:

```bash
a2a send \
  --url https://a2a.example.com/a2a \
  --ct task.v1 \
  --payload-file task.json \
  --tls-ca-file /etc/a2a/tls/ca.crt \
  --tls-client-cert-file /etc/a2a/tls/client.crt \
  --tls-client-key-file /etc/a2a/tls/client.key
```

## Security and Trust Features

- `--secure-required`: requires encrypted + signed + replay-protected inbound envelopes
- Key lifecycle controls: required key per agent, rotation sets, revocation, key expiry
- `trustsync.v1`: signed trust-registry discovery/proposal flow
- `session.v1`: negotiated binding handshake with optional detached signature
- Optional runtime migration policy: `--version-policy-file`

Fine-grained tool authorization policy:

```json
{
  "allowed_tools_by_agent": {
    "did:key:planner-a": ["math.add", "sys.ping"]
  },
  "required_scopes_by_tool": {
    "math.add": "tool:math.add"
  }
}
```

```bash
a2a serve --tool-policy-file tool_policy.json
```

## Transport and Extensibility

- HTTP transport: reference implementation with retries/backoff and negotiation fallback
- WS transport: protocol-equivalent validation and error mapping
- IPC transport: local framed transport (`uint32_be`)
- Built-in handlers: `task.v1`, `toolcall.v1`, `negotiation.v1`, `trustsync.v1`, `session.v1`
- Custom handlers: `--handler-spec <ct>=<module>:<callable>`

## Operations

- Observability endpoints: `/healthz`, `/readyz`, `/metrics`
- Audit chain: append-only hash chain with optional Ed25519 receipts
- External audit anchoring: `--audit-anchor-url` (+ optional fail-closed mode)

## Advanced

- Multi-buddy Codex swarm orchestration is available via `a2a swarm` for iterative protocol work.
- Versioning policy details: `docs/versioning-policy.md`

## Test

```bash
python3 -m unittest discover -s tests -v
```

```bash
a2a conformance --transport all --mode all --format text
```

## Release (Maintainers)

Trusted publishing is configured through GitHub Actions (`publish-pypi.yml`) to PyPI project `a2acrpt`.

Release flow:

1. Bump version in `pyproject.toml`
2. Merge to `main`
3. Tag and push (for example `v0.1.1`)

```bash
git tag v0.1.1
git push origin v0.1.1
```

## Security Reporting

For potential vulnerabilities, use a private disclosure path (GitHub Security Advisory / private report) instead of a public issue.
