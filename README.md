# A2A-SDL (Reference Implementation)

A2A-SDL is a machine-optimized, self-describing protocol for cross-agent communication with strict validation, canonical encoding, and optional cryptographic security.

This repository implements:
- Envelope validation and limits (`max_bytes`, `max_depth`, `max_array_len`)
- JSON canonical encoding and optional canonical CBOR
- Embedded/URI schema descriptors with content-hash checks
- Optional JSON Schema validation (when `jsonschema` is installed)
- Ed25519 signing/verification
- X25519 + ChaCha20-Poly1305 payload encryption
- Replay nonce cache
- HTTP transport (stdlib server/client + optional FastAPI app)
- Local IPC transport binding (length-prefixed `uint32_be` frames)
- CLI for send/serve/keys/validation
- Structured error mapping for protocol validation failures (`UNSUPPORTED_CT`, `SCHEMA_INVALID`, `SECURITY_UNSUPPORTED`)
- HTTP client retries/backoff and configurable timeout (`a2a send --timeout --retry-attempts --retry-backoff-s`)
- Optional server-side replay enforcement (`a2a serve --replay-protection`)
- Trace enforcement with hop limits (`trace.root_id`, `trace.span_id`, `trace.hops`) and derived child trace on responses
- Optional automatic content-type negotiation fallback (`a2a send --auto-negotiate`)
- Secure policy mode for mandatory `enc+sig+replay`, key-based authz, and allowlisted agents
- Tamper-evident hash-chained audit log with optional Ed25519-signed audit receipts
- WebSocket transport processing now matches HTTP validation/security behavior with structured `error.v1` responses
- Built-in 3-buddy swarm command (`a2a swarm`) that coordinates Codex buddies through A2A envelopes
- Executable `toolcall.v1` path with built-in tools (`sys.ping`, `math.add`)
- Pluggable request handlers via `a2a serve --handler-spec <ct>=<module>:<callable>`
- Ingress hardening: oversized `Content-Length` rejected before body read
- URI-schema hardening: untrusted URI descriptors rejected on HTTP/WS/IPC ingress and transport client preflight
- Key lifecycle policy support: key rotation sets, revoked key IDs, and per-kid expiry checks
- Plugin safety controls: deny-by-default tool execution and strict custom handler module/manifest validation
- Stress and fuzz testing for malformed envelopes and concurrent HTTP load
- Durable replay protection via optional SQLite-backed nonce cache (`--replay-db-file`)
- Production transport controls: TLS/mTLS options and production deployment profile
- Admission control with concurrency + token-bucket rate limiting
- Audit signature verification support for signed audit chains

## How It Works

At runtime, every message is an envelope with:
- **Identity** (`from`, `to`) for routing and access-policy checks
- **Payload type** (`ct`) for handler dispatch and schema validation
- **Payload** (`payload`) with request/response body
- **Schema descriptor** (`schema`) for self-describing validation
- **Security** (`sec`) for signatures, encryption metadata, and replay tokens
- **Trace** (`trace`) for request lineage and hop control

Typical request flow:
1. Build envelope with `build_envelope(...)`.
2. Canonically encode (`json`, optional `cbor`) with deterministic ordering.
3. Optionally encrypt payload and attach replay nonce/expiry.
4. Optionally sign envelope.
5. Send over transport (`HTTP`, `WS`, or local `IPC`).
6. Receiver validates envelope, security policy, replay cache, and schema.
7. Handler returns a typed response envelope (`toolresult.v1`, `task.v1`, or `error.v1`).

## Project Structure

Core modules:
- `a2a_sdl/envelope.py`: envelope construction, validation limits, trace checks.
- `a2a_sdl/schema.py`: builtin descriptors, hash checks, JSON schema integration.
- `a2a_sdl/codec.py`: canonical JSON/CBOR encode/decode.
- `a2a_sdl/security.py`: Ed25519 signatures and X25519+ChaCha20-Poly1305 encryption.
- `a2a_sdl/policy.py`: secure-required policy enforcement (`enc+sig+replay`, key allowlists).
- `a2a_sdl/replay.py`: nonce cache for replay protection.
- `a2a_sdl/transport_http.py`: stdlib server/client, retries, fallback negotiation.
- `a2a_sdl/transport_ws.py`: websocket payload processing with protocol-aligned errors.
- `a2a_sdl/transport_ipc.py`: length-prefixed local IPC transport.
- `a2a_sdl/swarm.py`: multi-buddy Codex orchestration over A2A envelopes.
- `a2a_sdl/handlers.py`: content-type router, builtin handlers, and tool registry.
- `a2a_sdl/cli.py`: operational entrypoints (`send`, `serve`, `swarm`, `keygen`, etc).

Tests:
- `tests/` contains unit coverage for envelope rules, security, transports, policy, and swarm convergence behavior.

## Installation

Recommended (isolated CLI install with `uv`):

```bash
uv tool install "a2a-sdl[full]"
uv tool update-shell
```

From local checkout (editable dev install as a tool):

```bash
uv tool install --editable "/path/to/crpt[full]"
```

From GitHub (without publishing to PyPI):

```bash
uv tool install "git+https://github.com/psspssr/crpt.git"
```

One-off command execution without permanent install:

```bash
uv tool run --from "a2a-sdl[full]" a2a --help
```

Alternative installers:

```bash
pip install "a2a-sdl[full]"
pipx install "a2a-sdl[full]"
```

Useful extras:
- `a2a-sdl[cbor]` for CBOR codec support
- `a2a-sdl[schema]` for JSON Schema validation
- `a2a-sdl[http]` for FastAPI/uvicorn adapter
- `a2a-sdl[ws]` for websocket transport

## Quick Start

```bash
uv tool install --force "/root/crpt[full]"
a2a keygen --out-dir .keys
```

Send a task over HTTP:

```bash
a2a serve --host 127.0.0.1 --port 8080 --deployment-mode dev --allow-insecure-http
# in another shell:
a2a send --url http://127.0.0.1:8080/a2a --ct task.v1 --payload-file a2a_sdl/examples/task_min_payload.json --timeout 30 --retry-attempts 2 --retry-backoff-s 0.25 --auto-negotiate
```

Secure server mode (mandatory encrypted/signed inbound requests + audit log):

```bash
# trusted_signing_keys.json: { "<sender-kid>": "<ed25519-public-key>" }
# decrypt_keys.json: { "<server-recipient-kid>": "<x25519-private-key>" }
# agent_kid_map.json: { "<sender-agent-id>": "<sender-kid>" }

a2a serve \
  --host 127.0.0.1 --port 8080 \
  --deployment-mode prod \
  --secure-required \
  --tls-cert-file /etc/a2a/tls/server.crt \
  --tls-key-file /etc/a2a/tls/server.key \
  --replay-db-file /var/lib/a2a/replay.db \
  --trusted-signing-keys-file trusted_signing_keys.json \
  --decrypt-keys-file decrypt_keys.json \
  --agent-kid-map-file agent_kid_map.json \
  --allowed-agent did:key:sender-agent \
  --audit-log-file /tmp/a2a_audit.log
```

Key lifecycle controls (rotation + revocation):

```bash
# key_registry.json may include:
# trusted_signing_keys, required_kid_by_agent, allowed_kids_by_agent,
# revoked_kids, kid_not_after, decrypt_private_keys
a2a serve \
  --host 127.0.0.1 --port 8080 \
  --deployment-mode prod \
  --tls-cert-file /etc/a2a/tls/server.crt \
  --tls-key-file /etc/a2a/tls/server.key \
  --replay-db-file /var/lib/a2a/replay.db \
  --key-registry-file key_registry.json
```

Secure sender mode (`enc+sig+replay` auto-applied):

```bash
a2a send \
  --url http://127.0.0.1:8080/a2a \
  --ct task.v1 \
  --payload-file a2a_sdl/examples/task_min_payload.json \
  --secure \
  --sign-key .keys/ed25519_private.pem \
  --sign-kid did:key:sender-agent#sig1 \
  --encrypt-kid did:key:server#enc1 \
  --encrypt-pub .keys/x25519_public.b64
```

## Transport Details

- **HTTP**: reference request/response transport, retry/backoff support, content-type negotiation fallback.
- **WS**: same protocol validation path as HTTP; protocol violations map to structured `error.v1`.
- **IPC**: local framed transport (`uint32_be` + payload bytes), useful for same-host agent orchestration.

All transports converge on shared envelope validation and handler semantics to keep behavior consistent.

## Handler Extensibility (New)

Two extensibility layers are built in:
- **Tool registry for `toolcall.v1`**:
  - `sys.ping`: liveness + echo payload
  - `math.add`: numeric aggregation from `args.values`
- **Content-type router**:
  - default implementation for `task.v1`, `toolcall.v1`, `negotiation.v1`
  - custom content types can be registered at server startup

Protocol metadata improvement:
- response envelopes now advertise available tools in `cap.tools`
- negotiation responses include `payload.available_tools`

Example custom handler wiring:

```bash
a2a serve \
  --host 127.0.0.1 --port 8080 \
  --allow-handler-module-prefix myproject.handlers \
  --handler-spec artifact.v1=myproject.handlers:artifact_handler
```

`artifact_handler(request)` must return a valid A2A response envelope.

By default, tool execution is deny-by-default in `a2a serve`.
Allow tools explicitly:

```bash
a2a serve --allow-tool sys.ping --allow-tool math.add
```

Use `--unsafe-allow-unmanifested-handlers` only for trusted local development.

## Security Model

`--secure-required` mode on server enforces all of:
- encrypted payload (`enc`)
- valid trusted signature (`sig`)
- replay token with nonce + expiry (`replay`)
- sender identity/key mapping and optional allowlisted agent IDs

Operational components:
- `ReplayCache` blocks duplicate nonce usage.
- Audit chain can persist tamper-evident event history and optional signed receipts.
- Structured errors intentionally avoid leaking sensitive internals.

Programmatic local IPC usage:

```python
from a2a_sdl.handlers import default_handler
from a2a_sdl.transport_ipc import IPCServer, send_ipc
from tests.test_helpers import make_task_envelope

server = IPCServer("127.0.0.1", 9099, handler=default_handler)
# run server.serve_forever() in a background thread/process
response = send_ipc("127.0.0.1", 9099, make_task_envelope(), encoding="json")
```

3-buddy autonomous swarm (Codex-backed, A2A toolcall envelopes):

```bash
a2a swarm \
  --goal "Drive protocol to near-final feature completeness." \
  --ports 8211,8212,8213 \
  --rounds 8 \
  --near-final-rounds 2 \
  --workdir /root/crpt
```

Swarm report fields:
- `converged=true, mode=near_final`: majority of buddies reported `near_final` for the configured streak.
- `converged=true, mode=stabilized_working`: buddies remained `working` for multiple rounds with no major new feature movement.
- `converged=false, mode=not_converged`: max rounds reached without either condition.

Swarm behavior notes:
- Each buddy runs as an A2A HTTP endpoint backed by a `codex exec` call.
- Coordinator sends `toolcall.v1` requests round-by-round with handoff text chaining.
- Near-final convergence uses majority voting across buddies.
- If buddies stabilize in `working` state for repeated rounds, coordinator marks `stabilized_working` to avoid endless loops.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Release (Maintainers)

One-time setup:
1. Create a PyPI project named `a2a-sdl`.
2. In PyPI, add a Trusted Publisher for this GitHub repo/workflow.
3. In GitHub repo settings, create environment `pypi` (optional protection rules).

Automated release:
1. Bump version in `pyproject.toml`.
2. Commit and push to `main`.
3. Create and push a version tag (for example `v0.1.1`):
   `git tag v0.1.1 && git push origin v0.1.1`
4. GitHub Actions workflow `.github/workflows/publish-pypi.yml` builds and publishes to PyPI.

CI hardening workflow:
- `.github/workflows/ci.yml` runs lint (`ruff`), type checks (`mypy`), unit tests (3.11/3.12), and validates that `v*` tags match `pyproject.toml` version.

Manual local release check:
```bash
python -m pip install -U build twine
python -m build
python -m twine check dist/*
```

## Notes

- CBOR support requires `pip install -e .[cbor]`.
- JSON Schema validation requires `pip install -e .[schema]`.
- FastAPI server adapter requires `pip install -e .[http]`.
- Versioning policy details: `docs/versioning-policy.md`.
