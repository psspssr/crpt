# A2A-SDL Protocol v1 (Wire Specification)

This document defines the wire-level `v1` contract implemented by this repository.
It is intentionally strict and testable.

## Version And Scope

- Protocol major version: `v = 1`
- Envelope is required for every request/response/event.
- Supported message types: `req`, `res`, `evt`
- Supported built-in content types:
  - `task.v1`
  - `toolcall.v1`
  - `toolresult.v1`
  - `state.v1`
  - `artifact.v1`
  - `error.v1`
  - `negotiation.v1`
  - `trustsync.v1`
  - `session.v1`

## Envelope Contract

An envelope is a JSON object with required keys:

- `v` (integer, must equal `1`)
- `id` (non-empty string)
- `ts` (RFC3339 UTC string)
- `type` (`req` | `res` | `evt`)
- `from` (object with non-empty `agent_id`, `name`, `instance`, `role`)
- `to` (object with non-empty `agent_id`, `name`, `instance`, `role`)
- `cap` (object; contains peer capability metadata)
- `ct` (content-type string)
- `schema` (descriptor object, `embedded` or `uri`)
- `payload` (content-type-specific object/value)

Optional:

- `trace` object with:
  - `root_id` non-empty string
  - `span_id` non-empty string
  - `parent_span_id` non-empty string (optional)
  - `hops` integer `>= 0` and `<= max_hops`
- `sec` object for security mode and metadata.

### Validation Limits (Default)

- `max_bytes`: `1_048_576`
- `max_depth`: `64`
- `max_array_len`: `10_000`
- `max_hops`: `8`

## Security Semantics

Supported `sec.mode` values:

- `none`
- `sig`
- `enc`
- `enc+sig`

Supported algorithms:

- Signature: `ed25519`
- Encryption: `x25519-chacha20poly1305`

Optional replay block:

- `sec.replay.nonce` non-empty string
- `sec.replay.exp` RFC3339 UTC string

Replay validation behavior:

- Expired replay window is rejected.
- Duplicate nonce (per agent) is rejected when replay cache is enabled.

## Schema Descriptor Semantics

Descriptor object:

- `kind`: `embedded` or `uri`
- `id`: `sha256:<hex>`

If `kind=embedded`:

- `embedded` schema object is required.
- `id` must hash-match canonicalized `embedded` schema.

If `kind=uri`:

- `uri` is required.
- Runtime can disallow URI descriptors in transport contexts (HTTP/WS/IPC default path does).

## Error Envelope Semantics

All protocol-level failures return `ct = error.v1` with payload:

- `code` (`UNSUPPORTED_ENCODING`, `UNSUPPORTED_CT`, `SCHEMA_INVALID`, `SECURITY_UNSUPPORTED`, `BAD_REQUEST`, `INTERNAL`)
- `message` (string)
- `details` (object)
- `retryable` (boolean)

Error mapping rules:

- Unknown/invalid body encoding -> `UNSUPPORTED_ENCODING`
- Unsupported content type -> `UNSUPPORTED_CT`
- Schema descriptor or payload schema failure -> `SCHEMA_INVALID`
- Security mode/alg mismatch or security policy failure -> `SECURITY_UNSUPPORTED`
- Structural/request faults (invalid length, replay errors, malformed values) -> `BAD_REQUEST`
- Handler/internal runtime failure -> `INTERNAL`

## Canonical Wire Examples

### Example Request (`task.v1`)

```json
{
  "v": 1,
  "id": "msg-req-001",
  "ts": "2026-01-01T00:00:00Z",
  "type": "req",
  "from": {
    "agent_id": "did:key:sender",
    "name": "planner",
    "instance": "pod-a",
    "role": "planner"
  },
  "to": {
    "agent_id": "did:key:receiver",
    "name": "executor",
    "instance": "pod-b",
    "role": "executor"
  },
  "cap": {
    "a2a_sdl": {
      "v": 1,
      "enc": [
        "json"
      ],
      "sig": [
        "ed25519"
      ],
      "kex": [
        "x25519"
      ],
      "comp": []
    },
    "tools": [],
    "modalities": [
      "text"
    ],
    "limits": {
      "max_bytes": 1048576,
      "max_depth": 64,
      "max_array_len": 10000,
      "max_hops": 8
    }
  },
  "ct": "task.v1",
  "schema": {
    "kind": "embedded",
    "id": "sha256:<task-schema-hash>",
    "embedded": {
      "type": "object"
    }
  },
  "payload": {
    "kind": "task.v1",
    "goal": "Return short status",
    "inputs": {},
    "constraints": {
      "time_budget_s": 30,
      "compute_budget": "low",
      "safety": {}
    },
    "deliverables": [
      {
        "type": "text",
        "description": "status"
      }
    ],
    "acceptance": [
      "Single line"
    ],
    "context": {}
  }
}
```

### Example Success Response (`state.v1`)

```json
{
  "v": 1,
  "id": "msg-res-001",
  "ts": "2026-01-01T00:00:01Z",
  "type": "res",
  "from": {
    "agent_id": "did:key:receiver",
    "name": "executor",
    "instance": "pod-b",
    "role": "executor"
  },
  "to": {
    "agent_id": "did:key:sender",
    "name": "planner",
    "instance": "pod-a",
    "role": "planner"
  },
  "cap": {
    "a2a_sdl": {
      "v": 1,
      "enc": [
        "json"
      ],
      "sig": [
        "ed25519"
      ],
      "kex": [
        "x25519"
      ],
      "comp": []
    },
    "tools": [
      "math.add",
      "sys.ping"
    ],
    "modalities": [
      "text"
    ],
    "limits": {
      "max_bytes": 1048576,
      "max_depth": 64,
      "max_array_len": 10000,
      "max_hops": 8
    }
  },
  "ct": "state.v1",
  "schema": {
    "kind": "embedded",
    "id": "sha256:<state-schema-hash>",
    "embedded": {
      "type": "object"
    }
  },
  "payload": {
    "base": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "patch": [
      {
        "op": "add",
        "path": "/status",
        "value": "accepted"
      }
    ]
  }
}
```

### Example Error Response (`UNSUPPORTED_CT`)

```json
{
  "v": 1,
  "id": "msg-err-001",
  "ts": "2026-01-01T00:00:02Z",
  "type": "res",
  "from": {
    "agent_id": "did:key:receiver",
    "name": "executor",
    "instance": "pod-b",
    "role": "executor"
  },
  "to": {
    "agent_id": "did:key:sender",
    "name": "planner",
    "instance": "pod-a",
    "role": "planner"
  },
  "cap": {
    "a2a_sdl": {
      "v": 1,
      "enc": [
        "json"
      ],
      "sig": [
        "ed25519"
      ],
      "kex": [
        "x25519"
      ],
      "comp": []
    },
    "tools": [],
    "modalities": [
      "text"
    ],
    "limits": {
      "max_bytes": 1048576,
      "max_depth": 64,
      "max_array_len": 10000,
      "max_hops": 8
    }
  },
  "ct": "error.v1",
  "schema": {
    "kind": "embedded",
    "id": "sha256:<error-schema-hash>",
    "embedded": {
      "type": "object"
    }
  },
  "payload": {
    "code": "UNSUPPORTED_CT",
    "message": "unsupported ct: foo.v9",
    "details": {
      "supported_ct": [
        "artifact.v1",
        "error.v1",
        "negotiation.v1",
        "session.v1",
        "state.v1",
        "task.v1",
        "toolcall.v1",
        "toolresult.v1",
        "trustsync.v1"
      ]
    },
    "retryable": true
  }
}
```

## Interoperability Guidance

- Implementations should reject unknown protocol major versions.
- Implementations should preserve error codes and semantics above for deterministic client behavior.
- If URI schemas are enabled in custom deployments, URI fetch must remain hash-verified and SSRF-safe.
- For negotiation and downgrade flows, `UNSUPPORTED_CT` responses should include `details.supported_ct`.

