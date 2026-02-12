"""CLI entrypoint for A2A-SDL."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import pathlib
import sys
from typing import Any

from .audit import AuditChain
from .codec import decode_bytes
from .envelope import build_envelope, validate_envelope
from .handlers import HandlerFn, ToolExecutionPolicy, make_default_handler
from .policy import SecurityPolicy
from .schema import get_builtin_descriptor
from .security import (
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
)
from .replay import ReplayCache, SQLiteReplayCache
from .swarm import BuddyEndpoint, CodexBackend, CodexBuddyServer, SwarmCoordinator
from .transport_http import AdmissionController, A2AHTTPServer, send_http, send_http_with_auto_downgrade
from .utils import json_dumps_pretty, new_message_id, sha256_prefixed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="a2a", description="A2A-SDL CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate signing and encryption keypairs")
    keygen.add_argument("--out-dir", default=".keys", help="Output directory")
    keygen.set_defaults(func=_cmd_keygen)

    validate_cmd = subparsers.add_parser("validate", help="Validate an envelope file")
    validate_cmd.add_argument("--in-file", required=True, help="Envelope file path (.json or .cbor)")
    validate_cmd.add_argument("--encoding", choices=["json", "cbor"], default="json")
    validate_cmd.set_defaults(func=_cmd_validate)

    serve = subparsers.add_parser("serve", help="Run local HTTP A2A server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument(
        "--deployment-mode",
        choices=["prod", "dev"],
        default="prod",
        help="Deployment profile. prod enforces secure mode + TLS unless --allow-insecure-http is set.",
    )
    serve.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow plaintext HTTP without TLS (recommended only for local development).",
    )
    serve.add_argument("--tls-cert-file", help="TLS server certificate chain file (PEM)")
    serve.add_argument("--tls-key-file", help="TLS server private key file (PEM)")
    serve.add_argument("--tls-ca-file", help="TLS CA bundle for optional/required client cert validation")
    serve.add_argument("--tls-require-client-cert", action="store_true", help="Require mutual TLS client certs")
    serve.add_argument("--replay-protection", action="store_true", help="Enable sec.replay nonce cache checks")
    serve.add_argument("--replay-ttl", type=int, default=600, help="Replay nonce TTL in seconds")
    serve.add_argument("--replay-max-entries", type=int, default=10000, help="Replay cache max entries")
    serve.add_argument(
        "--replay-db-file",
        help="SQLite file for durable replay nonce storage (recommended in production).",
    )
    serve.add_argument(
        "--admission-max-concurrent",
        type=int,
        default=128,
        help="Maximum in-flight requests accepted concurrently.",
    )
    serve.add_argument(
        "--admission-rate-rps",
        type=float,
        default=256.0,
        help="Token refill rate (requests/second) for admission control.",
    )
    serve.add_argument(
        "--admission-burst",
        type=int,
        default=512,
        help="Admission burst size before throttling.",
    )
    serve.add_argument("--secure-required", action="store_true", help="Require enc+sig+replay and authz policy")
    serve.add_argument(
        "--allowed-agent",
        action="append",
        default=[],
        help="Allowed sender agent_id (repeatable). Ignored unless secure policy is enabled.",
    )
    serve.add_argument(
        "--trusted-signing-keys-file",
        help="JSON object mapping sec.kid -> Ed25519 public key (PEM or b64)",
    )
    serve.add_argument(
        "--agent-kid-map-file",
        help="JSON object mapping from.agent_id -> required sec.kid",
    )
    serve.add_argument(
        "--decrypt-keys-file",
        help="JSON object mapping recipient kid -> X25519 private key (PEM or b64)",
    )
    serve.add_argument(
        "--key-registry-file",
        help=(
            "JSON key registry containing trusted_signing_keys, required_kid_by_agent, "
            "allowed_kids_by_agent, revoked_kids, kid_not_after"
        ),
    )
    serve.add_argument(
        "--agent-kids-map-file",
        help="JSON object mapping from.agent_id -> allowed sec.kid[] rotation set",
    )
    serve.add_argument(
        "--revoked-kids-file",
        help="JSON array of revoked sec.kid values",
    )
    serve.add_argument(
        "--kid-not-after-file",
        help="JSON object mapping sec.kid -> RFC3339 timestamp",
    )
    serve.add_argument("--audit-log-file", help="Append-only audit log path")
    serve.add_argument("--audit-signing-key", help="Ed25519 private key path for signing audit entries")
    serve.add_argument(
        "--allow-tool",
        action="append",
        default=[],
        help="Allowlisted builtin tool name for toolcall execution (repeatable). Deny-by-default.",
    )
    serve.add_argument(
        "--max-tool-args-bytes",
        type=int,
        default=4096,
        help="Maximum JSON-serialized bytes for payload.args in toolcall execution",
    )
    serve.add_argument(
        "--handler-spec",
        action="append",
        default=[],
        help="Custom request handler mapping: <ct>=<module>:<callable>",
    )
    serve.add_argument(
        "--allow-handler-module-prefix",
        action="append",
        default=[],
        help="Trusted module prefix for --handler-spec (repeatable).",
    )
    serve.add_argument(
        "--unsafe-allow-unmanifested-handlers",
        action="store_true",
        help="Disable strict HANDLER_MANIFEST validation for custom handlers.",
    )
    serve.set_defaults(func=_cmd_serve)

    send = subparsers.add_parser("send", help="Send a message over HTTP")
    send.add_argument("--url", required=True)
    send.add_argument("--ct", required=True, help="Content type (task.v1, toolcall.v1, ...) ")

    payload_group = send.add_mutually_exclusive_group(required=True)
    payload_group.add_argument("--payload-file", help="Path to payload JSON file")
    payload_group.add_argument("--payload-json", help="Inline JSON payload")

    send.add_argument("--encoding", choices=["json", "cbor"], default="json")
    send.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    send.add_argument("--retry-attempts", type=int, default=0, help="Retry attempts on network timeout/failure")
    send.add_argument("--retry-backoff-s", type=float, default=0.0, help="Exponential backoff base in seconds")
    send.add_argument(
        "--auto-negotiate",
        action="store_true",
        help="On UNSUPPORTED_CT, retry with ct downgrade or negotiation.v1 fallback",
    )
    send.add_argument("--from-agent", default="did:key:sender")
    send.add_argument("--to-agent", default="did:key:receiver")
    send.add_argument("--from-name", default="sender")
    send.add_argument("--to-name", default="receiver")
    send.add_argument("--from-instance", default="cli")
    send.add_argument("--to-instance", default="server")
    send.add_argument("--from-role", default="planner")
    send.add_argument("--to-role", default="executor")

    send.add_argument("--sign-key", help="Ed25519 private key path (PEM or b64 raw)")
    send.add_argument("--sign-kid", help="Key id to place in sec.kid")
    send.add_argument("--encrypt-kid", help="Recipient key id")
    send.add_argument("--encrypt-pub", help="Recipient X25519 public key value (PEM or b64 raw)")
    send.add_argument("--secure", action="store_true", help="Enforce enc+sig+replay on outbound message")
    send.add_argument("--replay-ttl-s", type=int, default=300, help="Replay expiration seconds when --secure is set")

    send.set_defaults(func=_cmd_send)

    swarm = subparsers.add_parser("swarm", help="Run 3 Codex buddies over A2A and iterate to near-final state")
    swarm.add_argument(
        "--goal",
        default="Drive the A2A-SDL protocol/framework to near-final feature completeness.",
        help="Swarm objective",
    )
    swarm.add_argument("--host", default="127.0.0.1", help="Buddy bind host")
    swarm.add_argument(
        "--ports",
        default="8211,8212,8213",
        help="Comma-separated buddy ports (must be exactly 3 for this command)",
    )
    swarm.add_argument("--rounds", type=int, default=8, help="Maximum swarm rounds")
    swarm.add_argument("--near-final-rounds", type=int, default=2, help="Consecutive all-near_final rounds to stop")
    swarm.add_argument("--buddy-timeout", type=int, default=120, help="Per-buddy codex exec timeout seconds")
    swarm.add_argument("--workdir", default=".", help="Codex buddy working directory")
    swarm.set_defaults(func=_cmd_swarm)

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    signing = generate_signing_keypair()
    x25519 = generate_x25519_keypair()

    _write_text(out_dir / "ed25519_private.pem", signing["private_key_pem"])
    _write_text(out_dir / "ed25519_public.pem", signing["public_key_pem"])
    _write_text(out_dir / "ed25519_private.b64", signing["private_key_b64"])
    _write_text(out_dir / "ed25519_public.b64", signing["public_key_b64"])

    _write_text(out_dir / "x25519_private.pem", x25519["private_key_pem"])
    _write_text(out_dir / "x25519_public.pem", x25519["public_key_pem"])
    _write_text(out_dir / "x25519_private.b64", x25519["private_key_b64"])
    _write_text(out_dir / "x25519_public.b64", x25519["public_key_b64"])

    print(f"keys written to {out_dir}")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    raw = pathlib.Path(args.in_file).read_bytes()
    message = decode_bytes(raw, encoding=args.encoding)
    validate_envelope(message)
    print("valid")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    prod_mode = args.deployment_mode == "prod"
    effective_secure_required = bool(args.secure_required or prod_mode)

    replay_cache: ReplayCache | SQLiteReplayCache | None = None
    secure_policy_enabled = bool(
        effective_secure_required
        or args.trusted_signing_keys_file
        or args.agent_kid_map_file
        or args.agent_kids_map_file
        or args.decrypt_keys_file
        or args.key_registry_file
        or args.revoked_kids_file
        or args.kid_not_after_file
        or args.allowed_agent
    )

    effective_replay_protection = bool(args.replay_protection or secure_policy_enabled or prod_mode)

    security_policy = None
    if secure_policy_enabled:
        try:
            key_registry = _load_key_registry(args.key_registry_file) if args.key_registry_file else {}

            trusted_signing_keys = dict(key_registry.get("trusted_signing_keys", {}))
            if args.trusted_signing_keys_file:
                trusted_signing_keys.update(_load_json_map(args.trusted_signing_keys_file))

            required_kid_by_agent = dict(key_registry.get("required_kid_by_agent", {}))
            if args.agent_kid_map_file:
                required_kid_by_agent.update(_load_json_map(args.agent_kid_map_file))

            allowed_kids_by_agent = {
                key: set(values)
                for key, values in dict(key_registry.get("allowed_kids_by_agent", {})).items()
            }
            if args.agent_kids_map_file:
                override = _load_json_map_of_lists(args.agent_kids_map_file)
                for key, values in override.items():
                    allowed_kids_by_agent[key] = values

            revoked_kids = set(key_registry.get("revoked_kids", set()))
            if args.revoked_kids_file:
                revoked_kids.update(_load_json_list(args.revoked_kids_file))

            kid_not_after = dict(key_registry.get("kid_not_after", {}))
            if args.kid_not_after_file:
                kid_not_after.update(_load_json_map(args.kid_not_after_file))

            decrypt_private_keys = dict(key_registry.get("decrypt_private_keys", {}))
            if args.decrypt_keys_file:
                decrypt_private_keys.update(_load_json_map(args.decrypt_keys_file))
        except Exception as exc:
            print(f"failed to load secure policy files: {exc}", file=sys.stderr)
            return 2

        if effective_secure_required and (not trusted_signing_keys or not decrypt_private_keys):
            print(
                "--secure-required needs --trusted-signing-keys-file and --decrypt-keys-file",
                file=sys.stderr,
            )
            return 2

        security_policy = SecurityPolicy(
            require_mode="enc+sig" if effective_secure_required else None,
            require_replay=effective_secure_required,
            allowed_agents=set(args.allowed_agent),
            trusted_signing_keys=trusted_signing_keys,
            required_kid_by_agent=required_kid_by_agent,
            allowed_kids_by_agent=allowed_kids_by_agent,
            revoked_kids=revoked_kids,
            kid_not_after=kid_not_after,
            decrypt_private_keys=decrypt_private_keys,
        )

    if prod_mode and not args.allow_insecure_http:
        if not args.tls_cert_file or not args.tls_key_file:
            print(
                "prod deployment requires TLS; provide --tls-cert-file and --tls-key-file "
                "or use --allow-insecure-http for local-only testing",
                file=sys.stderr,
            )
            return 2
        if not args.replay_db_file:
            print("prod deployment requires durable replay storage: --replay-db-file", file=sys.stderr)
            return 2

    audit_chain = None
    if args.audit_log_file:
        try:
            signing_key = _load_key_material(args.audit_signing_key) if args.audit_signing_key else None
            audit_chain = AuditChain(args.audit_log_file, signing_private_key=signing_key)
        except Exception as exc:
            print(f"failed to initialize audit chain: {exc}", file=sys.stderr)
            return 2

    extra_handlers: dict[str, HandlerFn] = {}
    allowed_prefixes = tuple(dict.fromkeys(["a2a_sdl"] + list(args.allow_handler_module_prefix)))
    require_manifest = not args.unsafe_allow_unmanifested_handlers
    for spec in args.handler_spec:
        try:
            ct, handler = _load_handler_spec(
                spec,
                allowed_module_prefixes=allowed_prefixes,
                require_manifest=require_manifest,
            )
        except Exception as exc:
            print(f"invalid --handler-spec '{spec}': {exc}", file=sys.stderr)
            return 2
        extra_handlers[ct] = handler

    tool_policy = ToolExecutionPolicy(
        allowed_tools=set(args.allow_tool),
        max_args_bytes=max(1, int(args.max_tool_args_bytes)),
    )
    handler = make_default_handler(extra_handlers=extra_handlers, tool_execution_policy=tool_policy)
    admission_controller = AdmissionController(
        max_concurrent=max(1, int(args.admission_max_concurrent)),
        rate_limit_rps=max(0.0, float(args.admission_rate_rps)),
        burst=max(1, int(args.admission_burst)),
    )

    try:
        if effective_replay_protection:
            if args.replay_db_file:
                replay_cache = SQLiteReplayCache(
                    args.replay_db_file,
                    max_entries=args.replay_max_entries,
                    ttl_seconds=args.replay_ttl,
                )
            else:
                replay_cache = ReplayCache(max_entries=args.replay_max_entries, ttl_seconds=args.replay_ttl)
    except Exception as exc:
        print(f"failed to initialize replay cache: {exc}", file=sys.stderr)
        return 2

    try:
        server = A2AHTTPServer(
            args.host,
            args.port,
            handler=handler,
            replay_cache=replay_cache,
            enforce_replay=effective_replay_protection,
            security_policy=security_policy,
            audit_chain=audit_chain,
            tls_certfile=args.tls_cert_file,
            tls_keyfile=args.tls_key_file,
            tls_ca_file=args.tls_ca_file,
            tls_require_client_cert=args.tls_require_client_cert,
            admission_controller=admission_controller,
        )
    except Exception as exc:
        if isinstance(replay_cache, SQLiteReplayCache):
            replay_cache.close()
        print(f"failed to initialize server: {exc}", file=sys.stderr)
        return 2
    scheme = "https" if args.tls_cert_file and args.tls_key_file else "http"
    print(f"serving on {scheme}://{args.host}:{args.port}/a2a")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        if isinstance(replay_cache, SQLiteReplayCache):
            replay_cache.close()
    return 0


def _cmd_send(args: argparse.Namespace) -> int:
    payload = _load_payload(args.payload_file, args.payload_json)

    from_identity = {
        "agent_id": args.from_agent,
        "name": args.from_name,
        "instance": args.from_instance,
        "role": args.from_role,
    }
    to_identity = {
        "agent_id": args.to_agent,
        "name": args.to_name,
        "instance": args.to_instance,
        "role": args.to_role,
    }

    schema = get_builtin_descriptor(args.ct)
    if schema is None:
        # Fallback generic schema for unknown custom content types.
        schema = {
            "kind": "embedded",
            "embedded": {"type": "object"},
            "id": sha256_prefixed(b"{\"type\":\"object\"}"),
        }

    envelope = build_envelope(
        msg_type="req",
        from_identity=from_identity,
        to_identity=to_identity,
        content_type=args.ct,
        payload=payload,
        schema=schema,
    )

    encrypt_pub_value = _load_key_material(args.encrypt_pub) if args.encrypt_pub else None

    if args.secure:
        if not args.sign_key or not args.sign_kid or not args.encrypt_kid or not encrypt_pub_value:
            print(
                "--secure requires --sign-key --sign-kid --encrypt-kid --encrypt-pub",
                file=sys.stderr,
            )
            return 2
        sign_key_value = _load_key_material(args.sign_key)

        encrypt_payload(
            envelope,
            recipients=[{"kid": args.encrypt_kid, "public_key": encrypt_pub_value}],
        )
        _attach_replay(envelope, ttl_seconds=args.replay_ttl_s)
        sign_envelope(envelope, sign_key_value, kid=args.sign_kid)
    else:
        if encrypt_pub_value:
            if not args.encrypt_kid:
                print("--encrypt-kid is required when --encrypt-pub is set", file=sys.stderr)
                return 2
            encrypt_payload(
                envelope,
                recipients=[{"kid": args.encrypt_kid, "public_key": encrypt_pub_value}],
            )

        if args.sign_key:
            sign_key_value = _load_key_material(args.sign_key)
            sign_envelope(envelope, sign_key_value, kid=args.sign_kid)

    validate_envelope(envelope, validate_payload_schema=False if args.encrypt_pub else True)

    send_fn = send_http_with_auto_downgrade if args.auto_negotiate else send_http
    response = send_fn(
        args.url,
        envelope,
        encoding=args.encoding,
        timeout=args.timeout,
        retry_attempts=args.retry_attempts,
        retry_backoff_s=args.retry_backoff_s,
    )
    print(json_dumps_pretty(response))
    return 0


def _cmd_swarm(args: argparse.Namespace) -> int:
    try:
        ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
    except ValueError:
        print("--ports must be a comma-separated list of integers", file=sys.stderr)
        return 2

    if len(ports) != 3:
        print("--ports must contain exactly 3 ports for 3 buddies", file=sys.stderr)
        return 2

    buddies: list[CodexBuddyServer] = []
    endpoints: list[BuddyEndpoint] = []
    try:
        for idx, port in enumerate(ports, start=1):
            name = f"buddy-{idx}"
            backend = CodexBackend(workdir=args.workdir, timeout_s=args.buddy_timeout)
            buddy = CodexBuddyServer(name=name, host=args.host, port=port, backend=backend)
            buddy.start()
            buddies.append(buddy)
            endpoints.append(BuddyEndpoint(name=name, url=buddy.url))

        coordinator_timeout = max(float(args.buddy_timeout) + 10.0, 15.0)
        coordinator = SwarmCoordinator(
            endpoints,
            timeout_s=coordinator_timeout,
            retry_attempts=1,
            retry_backoff_s=0.2,
        )
        report = coordinator.run(goal=args.goal, max_rounds=args.rounds, near_final_rounds=args.near_final_rounds)
        print(json_dumps_pretty(report))
        return 0
    finally:
        for buddy in buddies:
            buddy.stop()


def _load_payload(payload_file: str | None, payload_json: str | None) -> Any:
    if payload_file:
        return json.loads(pathlib.Path(payload_file).read_text(encoding="utf-8"))
    assert payload_json is not None
    return json.loads(payload_json)


def _write_text(path: pathlib.Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


_ALLOWED_HANDLER_PERMISSIONS = {"read_payload", "write_response", "emit_metrics"}


def _load_handler_spec(
    spec: str,
    *,
    allowed_module_prefixes: tuple[str, ...] | None = None,
    require_manifest: bool = False,
) -> tuple[str, HandlerFn]:
    if "=" not in spec:
        raise ValueError("expected format <ct>=<module>:<callable>")
    content_type, target = spec.split("=", 1)
    ct = content_type.strip()
    if not ct:
        raise ValueError("content type is empty")

    if ":" not in target:
        raise ValueError("expected handler target format <module>:<callable>")
    module_name, attr_name = target.rsplit(":", 1)
    module_name = module_name.strip()
    attr_name = attr_name.strip()
    if not module_name or not attr_name:
        raise ValueError("module and callable must be non-empty")
    if allowed_module_prefixes:
        if not any(
            module_name == prefix or module_name.startswith(f"{prefix}.")
            for prefix in allowed_module_prefixes
        ):
            raise ValueError(f"module '{module_name}' is not in allowed handler prefixes")

    module = importlib.import_module(module_name)
    _validate_handler_manifest(module, content_type=ct, require_manifest=require_manifest)
    handler = getattr(module, attr_name, None)
    if handler is None:
        raise ValueError(f"callable '{attr_name}' not found in module '{module_name}'")
    if not callable(handler):
        raise TypeError(f"attribute '{attr_name}' in module '{module_name}' is not callable")

    return ct, handler


def _validate_handler_manifest(module: Any, *, content_type: str, require_manifest: bool) -> None:
    manifest = getattr(module, "HANDLER_MANIFEST", None)
    if manifest is None:
        if require_manifest:
            raise ValueError("module must define HANDLER_MANIFEST in strict mode")
        return
    if not isinstance(manifest, dict):
        raise ValueError("HANDLER_MANIFEST must be an object")

    name = manifest.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("HANDLER_MANIFEST.name must be a non-empty string")

    content_types = manifest.get("content_types")
    if not isinstance(content_types, list) or not all(isinstance(item, str) and item for item in content_types):
        raise ValueError("HANDLER_MANIFEST.content_types must be a non-empty string array")
    if content_type not in content_types:
        raise ValueError(f"HANDLER_MANIFEST.content_types does not include '{content_type}'")

    permissions = manifest.get("permissions", [])
    if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
        raise ValueError("HANDLER_MANIFEST.permissions must be a string array")
    unknown = sorted(set(permissions) - _ALLOWED_HANDLER_PERMISSIONS)
    if unknown:
        raise ValueError(f"HANDLER_MANIFEST has unsupported permissions: {unknown}")


def _load_json_map(path: str) -> dict[str, str]:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError(f"{path} must contain a JSON object")

    result: dict[str, str] = {}
    for key, value in decoded.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"{path} must map string->string values")
        result[key] = value
    return result


def _load_json_map_of_lists(path: str) -> dict[str, set[str]]:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    result: dict[str, set[str]] = {}
    for key, value in decoded.items():
        if not isinstance(key, str) or not isinstance(value, list):
            raise ValueError(f"{path} must map string->string[] values")
        if not all(isinstance(item, str) and item for item in value):
            raise ValueError(f"{path} must map string->non-empty string[] values")
        result[key] = set(value)
    return result


def _load_json_list(path: str) -> list[str]:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, list) or not all(isinstance(item, str) and item for item in decoded):
        raise ValueError(f"{path} must contain a string array")
    return decoded


def _load_key_registry(path: str) -> dict[str, Any]:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError(f"{path} must contain a JSON object")

    registry: dict[str, Any] = {
        "trusted_signing_keys": {},
        "required_kid_by_agent": {},
        "allowed_kids_by_agent": {},
        "revoked_kids": set(),
        "kid_not_after": {},
        "decrypt_private_keys": {},
    }

    if "trusted_signing_keys" in decoded:
        if not isinstance(decoded["trusted_signing_keys"], dict):
            raise ValueError("trusted_signing_keys must be an object")
        registry["trusted_signing_keys"] = {
            str(key): str(value) for key, value in decoded["trusted_signing_keys"].items()
        }
    if "required_kid_by_agent" in decoded:
        if not isinstance(decoded["required_kid_by_agent"], dict):
            raise ValueError("required_kid_by_agent must be an object")
        registry["required_kid_by_agent"] = {
            str(key): str(value) for key, value in decoded["required_kid_by_agent"].items()
        }
    if "allowed_kids_by_agent" in decoded:
        if not isinstance(decoded["allowed_kids_by_agent"], dict):
            raise ValueError("allowed_kids_by_agent must be an object")
        parsed: dict[str, set[str]] = {}
        for key, value in decoded["allowed_kids_by_agent"].items():
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError("allowed_kids_by_agent must map to string arrays")
            parsed[str(key)] = set(value)
        registry["allowed_kids_by_agent"] = parsed
    if "revoked_kids" in decoded:
        if not isinstance(decoded["revoked_kids"], list) or not all(isinstance(item, str) for item in decoded["revoked_kids"]):
            raise ValueError("revoked_kids must be a string array")
        registry["revoked_kids"] = set(decoded["revoked_kids"])
    if "kid_not_after" in decoded:
        if not isinstance(decoded["kid_not_after"], dict):
            raise ValueError("kid_not_after must be an object")
        registry["kid_not_after"] = {str(key): str(value) for key, value in decoded["kid_not_after"].items()}
    if "decrypt_private_keys" in decoded:
        if not isinstance(decoded["decrypt_private_keys"], dict):
            raise ValueError("decrypt_private_keys must be an object")
        registry["decrypt_private_keys"] = {
            str(key): str(value) for key, value in decoded["decrypt_private_keys"].items()
        }

    return registry


def _load_key_material(value: str) -> str:
    path = pathlib.Path(value)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return value.strip()


def _attach_replay(envelope: dict[str, Any], *, ttl_seconds: int) -> None:
    ttl = max(1, ttl_seconds)
    exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl)).replace(microsecond=0)
    sec = envelope.setdefault("sec", {})
    sec["replay"] = {
        "nonce": new_message_id(),
        "exp": exp.isoformat().replace("+00:00", "Z"),
    }


if __name__ == "__main__":
    raise SystemExit(main())
