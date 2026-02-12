"""Schema descriptors and payload validation."""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.request
from urllib.parse import urlparse
from typing import Any, Callable

from .utils import canonical_json_bytes, sha256_prefixed

try:
    import jsonschema as _jsonschema
except Exception:  # pragma: no cover - optional dependency
    _jsonschema = None


class SchemaValidationError(ValueError):
    """Raised when schema descriptors or payload validation fails."""


TASK_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["kind", "goal", "inputs", "constraints", "deliverables", "acceptance", "context"],
    "properties": {
        "kind": {"const": "task.v1"},
        "goal": {"type": "string", "minLength": 1},
        "inputs": {"type": "object"},
        "constraints": {
            "type": "object",
            "required": ["time_budget_s", "compute_budget", "safety"],
            "properties": {
                "time_budget_s": {"type": "integer", "minimum": 0},
                "compute_budget": {"enum": ["low", "med", "high"]},
                "safety": {"type": "object"},
            },
        },
        "deliverables": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "description"],
                "properties": {
                    "type": {"enum": ["text", "json", "file", "patch"]},
                    "description": {"type": "string"},
                },
            },
        },
        "acceptance": {"type": "array", "items": {"type": "string"}},
        "context": {"type": "object"},
    },
}

TOOLCALL_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["tool", "call_id", "args", "expect"],
    "properties": {
        "tool": {"type": "string", "minLength": 1},
        "call_id": {"type": "string", "minLength": 1},
        "args": {"type": "object"},
        "expect": {"type": "object"},
        "authz": {
            "type": "object",
            "properties": {
                "scopes": {"type": "array", "items": {"type": "string"}},
                "delegated_by": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
    },
}

TOOLRESULT_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["call_id", "ok", "result", "logs", "metrics"],
    "properties": {
        "call_id": {"type": "string"},
        "ok": {"type": "boolean"},
        "result": {},
        "logs": {"type": "array", "items": {"type": "string"}},
        "metrics": {"type": "object"},
    },
}

STATE_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["base", "patch"],
    "properties": {
        "base": {"type": "string"},
        "patch": {"type": "array", "items": {"type": "object"}},
    },
}

ARTIFACT_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["items", "refs"],
    "properties": {
        "items": {"type": "array", "items": {"type": "object"}},
        "refs": {"type": "array", "items": {"type": "object"}},
    },
}

ERROR_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["code", "message", "details", "retryable"],
    "properties": {
        "code": {
            "enum": [
                "UNSUPPORTED_ENCODING",
                "UNSUPPORTED_CT",
                "SCHEMA_INVALID",
                "SECURITY_UNSUPPORTED",
                "BAD_REQUEST",
                "INTERNAL",
            ]
        },
        "message": {"type": "string"},
        "details": {"type": "object"},
        "retryable": {"type": "boolean"},
    },
}

NEGOTIATION_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["need", "have", "ask", "supported_ct"],
    "properties": {
        "need": {"type": "object"},
        "have": {"type": "object"},
        "ask": {"type": "array", "items": {"type": "string"}},
        "supported_ct": {"type": "array", "items": {"type": "string"}},
        "session_binding": {"type": "object"},
    },
}

TRUSTSYNC_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["op"],
    "properties": {
        "op": {"enum": ["discover", "propose"]},
        "proposal_id": {"type": "string"},
        "merge": {"type": "boolean"},
        "registry": {"type": "object"},
        "signature": {"type": "string"},
        "approvals": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["approver", "signature"],
                "properties": {
                    "approver": {"type": "string"},
                    "signature": {"type": "string"},
                },
            },
        },
        "status": {"enum": ["snapshot", "accepted", "rejected"]},
        "message": {"type": "string"},
        "registry_hash": {"type": "string"},
        "snapshot": {"type": "object"},
        "source_agent": {"type": "string"},
        "approved_by": {"type": "array", "items": {"type": "string"}},
        "quorum": {"type": "object"},
    },
}

SESSION_V1_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["op", "profile", "nonce"],
    "properties": {
        "op": {"enum": ["open", "ack"]},
        "profile": {"type": "object"},
        "nonce": {"type": "string", "minLength": 8},
        "expires": {"type": "string"},
        "accepted": {"type": "boolean"},
        "binding_id": {"type": "string"},
        "binding_sig": {"type": "string"},
        "binding_alg": {"type": "string"},
        "message": {"type": "string"},
    },
}

BUILTIN_SCHEMAS: dict[str, dict[str, Any]] = {
    "task.v1": TASK_V1_SCHEMA,
    "toolcall.v1": TOOLCALL_V1_SCHEMA,
    "toolresult.v1": TOOLRESULT_V1_SCHEMA,
    "state.v1": STATE_V1_SCHEMA,
    "artifact.v1": ARTIFACT_V1_SCHEMA,
    "error.v1": ERROR_V1_SCHEMA,
    "negotiation.v1": NEGOTIATION_V1_SCHEMA,
    "trustsync.v1": TRUSTSYNC_V1_SCHEMA,
    "session.v1": SESSION_V1_SCHEMA,
}


Fetcher = Callable[[str], dict[str, Any]]


def schema_id(schema: dict[str, Any]) -> str:
    return sha256_prefixed(canonical_json_bytes(schema))


def make_embedded_schema(schema: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "embedded", "id": schema_id(schema), "embedded": schema}


def get_builtin_descriptor(content_type: str) -> dict[str, Any] | None:
    schema = BUILTIN_SCHEMAS.get(content_type)
    if schema is None:
        return None
    return make_embedded_schema(schema)


def validate_schema_descriptor(descriptor: dict[str, Any]) -> None:
    if not isinstance(descriptor, dict):
        raise SchemaValidationError("schema descriptor must be an object")

    kind = descriptor.get("kind")
    if kind not in {"embedded", "uri"}:
        raise SchemaValidationError("schema.kind must be 'embedded' or 'uri'")

    schema_hash = descriptor.get("id")
    if not isinstance(schema_hash, str) or not schema_hash.startswith("sha256:"):
        raise SchemaValidationError("schema.id must be a sha256-prefixed string")

    if kind == "embedded":
        embedded = descriptor.get("embedded")
        if not isinstance(embedded, dict):
            raise SchemaValidationError("schema.embedded must be present for embedded schema")
        expected = schema_id(embedded)
        if expected != schema_hash:
            raise SchemaValidationError("schema.id does not match embedded schema hash")
    else:
        uri = descriptor.get("uri")
        if not isinstance(uri, str) or not uri:
            raise SchemaValidationError("schema.uri must be present for uri schema")


def _default_fetcher(uri: str) -> dict[str, Any]:
    parsed = urlparse(uri)
    if parsed.scheme not in {"https", "http"}:
        raise SchemaValidationError("schema.uri scheme must be http or https")
    if parsed.username or parsed.password:
        raise SchemaValidationError("schema.uri must not include credentials")
    host = parsed.hostname
    if not host:
        raise SchemaValidationError("schema.uri must include a host")
    if _host_is_local_or_private(host):
        raise SchemaValidationError("schema.uri host must resolve to public addresses")

    # Host/scheme are validated above before making a network fetch.
    with urllib.request.urlopen(uri, timeout=5) as response:  # nosec B310
        data = response.read()
    decoded = json.loads(data.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise SchemaValidationError("fetched schema must be a JSON object")
    return decoded


def _host_is_local_or_private(host: str) -> bool:
    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(".local"):
        return True

    try:
        direct_ip = ipaddress.ip_address(lowered)
    except ValueError:
        direct_ip = None
    if direct_ip is not None:
        return _ip_is_local_or_private(direct_ip)

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise SchemaValidationError(f"schema.uri host resolution failed: {host}") from exc

    for info in infos:
        sockaddr = info[4]
        if not isinstance(sockaddr, tuple) or not sockaddr:
            continue
        raw_ip = sockaddr[0]
        try:
            resolved_ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if _ip_is_local_or_private(resolved_ip):
            return True
    return False


def _ip_is_local_or_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_schema(descriptor: dict[str, Any], fetcher: Fetcher | None = None) -> dict[str, Any]:
    validate_schema_descriptor(descriptor)

    if descriptor["kind"] == "embedded":
        return descriptor["embedded"]

    fetch = fetcher or _default_fetcher
    schema = fetch(descriptor["uri"])
    resolved_id = schema_id(schema)
    if resolved_id != descriptor["id"]:
        raise SchemaValidationError("fetched schema hash mismatch")
    return schema


def validate_payload(
    payload: Any,
    descriptor: dict[str, Any],
    fetcher: Fetcher | None = None,
) -> None:
    schema = resolve_schema(descriptor, fetcher=fetcher)
    if _jsonschema is not None:
        try:
            _jsonschema.validate(instance=payload, schema=schema)
            return
        except Exception as exc:  # pragma: no cover - depends on optional dep
            raise SchemaValidationError(f"jsonschema validation failed: {exc}") from exc

    _basic_validate(payload, schema)


def _basic_validate(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected const {schema['const']!r}")

    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise SchemaValidationError(f"{path}: value not in enum")

    if "anyOf" in schema:
        options = schema["anyOf"]
        for option in options:
            try:
                _basic_validate(value, option, path)
                break
            except SchemaValidationError:
                continue
        else:
            raise SchemaValidationError(f"{path}: no anyOf branch matched")

    if "oneOf" in schema:
        options = schema["oneOf"]
        matches = 0
        for option in options:
            try:
                _basic_validate(value, option, path)
                matches += 1
            except SchemaValidationError:
                continue
        if matches != 1:
            raise SchemaValidationError(f"{path}: oneOf expected exactly one match")

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        raise SchemaValidationError(f"{path}: expected type {expected_type!r}")

    if isinstance(value, str):
        min_len = schema.get("minLength")
        if isinstance(min_len, int) and len(value) < min_len:
            raise SchemaValidationError(f"{path}: string shorter than minLength {min_len}")
        max_len = schema.get("maxLength")
        if isinstance(max_len, int) and len(value) > max_len:
            raise SchemaValidationError(f"{path}: string longer than maxLength {max_len}")

    if isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, int | float) and value < minimum:
            raise SchemaValidationError(f"{path}: value below minimum {minimum}")
        maximum = schema.get("maximum")
        if isinstance(maximum, int | float) and value > maximum:
            raise SchemaValidationError(f"{path}: value above maximum {maximum}")

    if isinstance(value, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            raise SchemaValidationError(f"{path}: array shorter than minItems {min_items}")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(value) > max_items:
            raise SchemaValidationError(f"{path}: array longer than maxItems {max_items}")

        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                _basic_validate(item, item_schema, f"{path}[{idx}]")

    if isinstance(value, dict):
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    raise SchemaValidationError(f"{path}: missing required key '{key}'")

        properties = schema.get("properties")
        if isinstance(properties, dict):
            for key, prop_schema in properties.items():
                if key in value and isinstance(prop_schema, dict):
                    _basic_validate(value[key], prop_schema, f"{path}.{key}")

        additional = schema.get("additionalProperties", True)
        if additional is False and isinstance(properties, dict):
            unknown = set(value.keys()) - set(properties.keys())
            if unknown:
                raise SchemaValidationError(f"{path}: additional properties not allowed: {sorted(unknown)!r}")


def _matches_type(value: Any, expected_type: Any) -> bool:
    if isinstance(expected_type, list):
        return any(_matches_type(value, item) for item in expected_type)

    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None

    return True
