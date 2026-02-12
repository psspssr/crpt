"""CLI entrypoint for A2A-SDL."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import pathlib
import sys
from typing import Any

from .audit import AuditChain, HTTPAuditAnchor
from .codec import decode_bytes
from .conformance import render_conformance_json, render_conformance_text, run_conformance_suite
from .envelope import build_envelope, validate_envelope
from .handlers import HandlerFn, ToolExecutionPolicy, TrustGovernancePolicy, make_default_handler
from .policy import SecurityPolicy, SecurityPolicyManager
from .schema import get_builtin_descriptor
from .security import (
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
)
from .replay import RedisReplayCache, ReplayCache, SQLiteReplayCache
from .session import SessionBindingStore
from .swarm import BuddyEndpoint, CodexBackend, CodexBuddyServer, SwarmCoordinator
from .transport_http import AdmissionController, A2AHTTPServer, send_http, send_http_with_auto_downgrade
from .utils import json_dumps_pretty, new_message_id, sha256_prefixed
from .versioning import parse_runtime_version_policy


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
    serve.add_argument("--host", default="127.0.0.1")
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
        "--replay-redis-url",
        help="Redis URL for distributed replay cache (shared across nodes).",
    )
    serve.add_argument(
        "--replay-redis-prefix",
        default="a2a:replay",
        help="Redis key prefix for replay entries.",
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
    serve.add_argument(
        "--admin-endpoints",
        action="store_true",
        help="Expose operational GET endpoints: /healthz, /readyz, /metrics",
    )
    serve.add_argument(
        "--admin-token",
        help="Optional shared token required for /readyz and /metrics (Authorization: Bearer <token>)",
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
    serve.add_argument("--audit-anchor-url", help="Optional HTTP(S) endpoint for external audit anchoring")
    serve.add_argument("--audit-anchor-token", help="Bearer token for audit anchor endpoint")
    serve.add_argument("--audit-anchor-timeout-s", type=float, default=5.0, help="Audit anchor HTTP timeout seconds")
    serve.add_argument(
        "--audit-anchor-fail-closed",
        action="store_true",
        help="Fail request processing if audit anchoring fails",
    )
    serve.add_argument("--audit-anchor-tls-ca-file", help="CA bundle for audit anchor TLS")
    serve.add_argument("--audit-anchor-tls-client-cert-file", help="Client cert PEM for audit anchor mTLS")
    serve.add_argument("--audit-anchor-tls-client-key-file", help="Client key PEM for audit anchor mTLS")
    serve.add_argument(
        "--audit-anchor-tls-insecure-skip-verify",
        action="store_true",
        help="Skip audit anchor TLS verification (debug only)",
    )
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
        "--tool-policy-file",
        help="JSON policy for per-agent tool grants and per-tool required scopes",
    )
    serve.add_argument("--version-policy-file", help="JSON runtime version/deprecation policy")
    serve.add_argument(
        "--trust-sync-verify-key-file",
        help="Ed25519 public key path used to verify trustsync.v1 propose updates",
    )
    serve.add_argument(
        "--trust-governance-file",
        help=(
            "JSON quorum policy for trustsync.v1 propose approvals "
            "(approver_keys + threshold)"
        ),
    )
    serve.add_argument(
        "--session-binding-signing-key-file",
        help="Ed25519 private key path used to sign session.v1 binding acknowledgements",
    )
    serve.add_argument(
        "--session-binding-required",
        action="store_true",
        help="Require sec.session binding for non-exempt request content types.",
    )
    serve.add_argument(
        "--session-binding-exempt-ct",
        action="append",
        default=[],
        help="Content type exempt from session binding checks (repeatable).",
    )
    serve.add_argument(
        "--session-binding-max-entries",
        type=int,
        default=10000,
        help="Maximum active session bindings retained in memory.",
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
    send.add_argument("--tls-ca-file", help="CA bundle for HTTPS server verification")
    send.add_argument("--tls-client-cert-file", help="Client certificate PEM for mTLS")
    send.add_argument("--tls-client-key-file", help="Client private key PEM for mTLS")
    send.add_argument(
        "--tls-insecure-skip-verify",
        action="store_true",
        help="Skip TLS certificate verification (debug only)",
    )
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
    send.add_argument("--session-binding-id", help="Attach sec.session.binding_id to bind request to an active session")
    send.add_argument("--session-binding-exp", help="Optional sec.session.exp timestamp (RFC3339)")

    send.set_defaults(func=_cmd_send)

    swarm = subparsers.add_parser("swarm", help="Run Codex buddies over A2A and iterate to near-final state")
    swarm.add_argument(
        "--goal",
        default="Drive the A2A-SDL protocol/framework to near-final feature completeness.",
        help="Swarm objective",
    )
    swarm.add_argument("--host", default="127.0.0.1", help="Buddy bind host")
    swarm.add_argument(
        "--ports",
        default="8211,8212,8213",
        help="Comma-separated buddy ports (minimum 2 for feedback-loop operation)",
    )
    swarm.add_argument("--rounds", type=int, default=8, help="Maximum swarm rounds")
    swarm.add_argument("--near-final-rounds", type=int, default=2, help="Consecutive all-near_final rounds to stop")
    swarm.add_argument("--buddy-timeout", type=int, default=120, help="Per-buddy codex exec timeout seconds")
    swarm.add_argument("--workdir", default=".", help="Codex buddy working directory")
    swarm.set_defaults(func=_cmd_swarm)

    conformance = subparsers.add_parser("conformance", help="Run protocol conformance suite")
    conformance.add_argument(
        "--transport",
        action="append",
        choices=["all", "core", "http", "ipc", "ws"],
        default=[],
        help="Transport profile to test (repeatable). Defaults to all.",
    )
    conformance.add_argument(
        "--mode",
        action="append",
        choices=["all", "dev", "secure"],
        default=[],
        help="Security mode profile to test (repeatable). Defaults to all.",
    )
    conformance.add_argument(
        "--skip-load",
        action="store_true",
        help="Skip concurrent load scenarios.",
    )
    conformance.add_argument(
        "--load-requests",
        type=int,
        default=24,
        help="Number of requests for each load scenario.",
    )
    conformance.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds for networked conformance cases.",
    )
    conformance.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    conformance.set_defaults(func=_cmd_conformance)

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

    replay_cache: ReplayCache | SQLiteReplayCache | RedisReplayCache | None = None
    version_policy = None
    if args.version_policy_file:
        try:
            raw_version_policy = json.loads(pathlib.Path(args.version_policy_file).read_text(encoding="utf-8"))
            version_policy = parse_runtime_version_policy(raw_version_policy)
        except Exception as exc:
            print(f"failed to load version policy: {exc}", file=sys.stderr)
            return 2

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
        or args.session_binding_required
    )

    effective_replay_protection = bool(args.replay_protection or secure_policy_enabled or prod_mode)

    security_policy: SecurityPolicy | None = None
    session_binding_store = SessionBindingStore(max_entries=max(1, int(args.session_binding_max_entries)))
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

        if args.session_binding_required and not trusted_signing_keys:
            print(
                "--session-binding-required needs trusted signing keys "
                "(--trusted-signing-keys-file or --key-registry-file)",
                file=sys.stderr,
            )
            return 2

        if effective_secure_required and (not trusted_signing_keys or not decrypt_private_keys):
            print(
                "--secure-required needs --trusted-signing-keys-file and --decrypt-keys-file",
                file=sys.stderr,
            )
            return 2

        exempt_ct = set(args.session_binding_exempt_ct)
        exempt_ct.update({"session.v1", "error.v1", "negotiation.v1"})
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
            require_session_binding=bool(args.session_binding_required),
            session_binding_store=session_binding_store,
            session_binding_exempt_ct=exempt_ct,
        )

    trust_policy_manager = SecurityPolicyManager(security_policy) if security_policy is not None else None
    trust_sync_verify_key = None
    if args.trust_sync_verify_key_file:
        try:
            trust_sync_verify_key = _load_key_material(args.trust_sync_verify_key_file)
        except Exception as exc:
            print(f"failed to load trust sync verify key: {exc}", file=sys.stderr)
            return 2

    trust_governance_policy = None
    if args.trust_governance_file:
        try:
            trust_governance_policy = _load_trust_governance_policy(args.trust_governance_file)
        except Exception as exc:
            print(f"failed to load trust governance policy: {exc}", file=sys.stderr)
            return 2

    if trust_governance_policy is not None and trust_sync_verify_key is not None:
        print(
            "use either --trust-governance-file or --trust-sync-verify-key-file, not both",
            file=sys.stderr,
        )
        return 2

    if trust_policy_manager is None and (trust_governance_policy is not None or trust_sync_verify_key is not None):
        trust_policy_manager = SecurityPolicyManager(SecurityPolicy())

    session_binding_signing_key = None
    if args.session_binding_signing_key_file:
        try:
            session_binding_signing_key = _load_key_material(args.session_binding_signing_key_file)
        except Exception as exc:
            print(f"failed to load session binding signing key: {exc}", file=sys.stderr)
            return 2

    if prod_mode and not args.allow_insecure_http:
        if not args.tls_cert_file or not args.tls_key_file:
            print(
                "prod deployment requires TLS; provide --tls-cert-file and --tls-key-file "
                "or use --allow-insecure-http for local-only testing",
                file=sys.stderr,
            )
            return 2
        if not args.replay_db_file and not args.replay_redis_url:
            print(
                "prod deployment requires durable replay storage: --replay-db-file or --replay-redis-url",
                file=sys.stderr,
            )
            return 2

    audit_chain = None
    if args.audit_log_file:
        try:
            signing_key = _load_key_material(args.audit_signing_key) if args.audit_signing_key else None
            anchor = None
            if args.audit_anchor_url:
                anchor = HTTPAuditAnchor(
                    args.audit_anchor_url,
                    timeout_s=args.audit_anchor_timeout_s,
                    token=args.audit_anchor_token,
                    tls_ca_file=args.audit_anchor_tls_ca_file,
                    tls_client_cert_file=args.audit_anchor_tls_client_cert_file,
                    tls_client_key_file=args.audit_anchor_tls_client_key_file,
                    tls_insecure_skip_verify=args.audit_anchor_tls_insecure_skip_verify,
                )
            audit_chain = AuditChain(
                args.audit_log_file,
                signing_private_key=signing_key,
                anchor=anchor,
                anchor_fail_closed=args.audit_anchor_fail_closed,
            )
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

    try:
        tool_policy_overrides = _load_tool_policy(args.tool_policy_file) if args.tool_policy_file else {}
    except Exception as exc:
        print(f"failed to load tool policy: {exc}", file=sys.stderr)
        return 2
    base_allowed_tools = set(args.allow_tool)
    file_allowed_tools = set(tool_policy_overrides.get("allowed_tools", set()))
    effective_allowed_tools = base_allowed_tools | file_allowed_tools
    tool_policy = ToolExecutionPolicy(
        allowed_tools=effective_allowed_tools,
        allowed_tools_by_agent=tool_policy_overrides.get("allowed_tools_by_agent", {}),
        required_scopes_by_tool=tool_policy_overrides.get("required_scopes_by_tool", {}),
        max_args_bytes=max(1, int(args.max_tool_args_bytes)),
    )
    handler = make_default_handler(
        extra_handlers=extra_handlers,
        tool_execution_policy=tool_policy,
        trust_policy_manager=trust_policy_manager,
        trust_update_verify_key=trust_sync_verify_key,
        trust_governance_policy=trust_governance_policy,
        session_binding_signing_key=session_binding_signing_key,
        session_binding_store=session_binding_store,
    )
    admission_controller = AdmissionController(
        max_concurrent=max(1, int(args.admission_max_concurrent)),
        rate_limit_rps=max(0.0, float(args.admission_rate_rps)),
        burst=max(1, int(args.admission_burst)),
    )
    admin_enabled = bool(args.admin_endpoints or args.admin_token)

    try:
        if effective_replay_protection:
            if args.replay_redis_url:
                replay_cache = RedisReplayCache(
                    args.replay_redis_url,
                    key_prefix=args.replay_redis_prefix,
                    ttl_seconds=args.replay_ttl,
                )
            elif args.replay_db_file:
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
            admin_enabled=admin_enabled,
            admin_token=args.admin_token,
            version_policy=version_policy,
        )
    except Exception as exc:
        _close_replay_cache(replay_cache)
        print(f"failed to initialize server: {exc}", file=sys.stderr)
        return 2
    scheme = "https" if args.tls_cert_file and args.tls_key_file else "http"
    print(f"serving on {scheme}://{args.host}:{args.port}/a2a")
    if admin_enabled:
        print(f"admin endpoints enabled on {scheme}://{args.host}:{args.port}/healthz")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        _close_replay_cache(replay_cache)
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

    if args.session_binding_id:
        sec = envelope.setdefault("sec", {})
        if not isinstance(sec, dict):
            sec = {}
            envelope["sec"] = sec
        if sec.get("mode") is None:
            sec["mode"] = "none"
        session_block: dict[str, str] = {"binding_id": args.session_binding_id}
        if args.session_binding_exp:
            session_block["exp"] = args.session_binding_exp
        sec["session"] = session_block

    validate_envelope(envelope, validate_payload_schema=not args.encrypt_pub)

    send_fn = send_http_with_auto_downgrade if args.auto_negotiate else send_http
    response = send_fn(
        args.url,
        envelope,
        encoding=args.encoding,
        timeout=args.timeout,
        retry_attempts=args.retry_attempts,
        retry_backoff_s=args.retry_backoff_s,
        tls_ca_file=args.tls_ca_file,
        tls_client_cert_file=args.tls_client_cert_file,
        tls_client_key_file=args.tls_client_key_file,
        tls_insecure_skip_verify=args.tls_insecure_skip_verify,
    )
    print(json_dumps_pretty(response))
    return 0


def _cmd_swarm(args: argparse.Namespace) -> int:
    try:
        ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
    except ValueError:
        print("--ports must be a comma-separated list of integers", file=sys.stderr)
        return 2

    if len(ports) < 2:
        print("--ports must contain at least 2 ports", file=sys.stderr)
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


def _cmd_conformance(args: argparse.Namespace) -> int:
    try:
        report = run_conformance_suite(
            transports=args.transport,
            modes=args.mode,
            include_load=not bool(args.skip_load),
            load_requests=max(1, int(args.load_requests)),
            timeout_s=max(0.1, float(args.timeout)),
        )
    except Exception as exc:
        print(f"failed to run conformance suite: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(render_conformance_json(report))
    else:
        print(render_conformance_text(report))
    return 0 if bool(report.get("passed")) else 1


def _load_payload(payload_file: str | None, payload_json: str | None) -> Any:
    if payload_file:
        return json.loads(pathlib.Path(payload_file).read_text(encoding="utf-8"))
    if payload_json is None:
        raise ValueError("payload_json is required when payload_file is not provided")
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


def _load_tool_policy(path: str) -> dict[str, Any]:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError(f"{path} must contain a JSON object")

    result: dict[str, Any] = {
        "allowed_tools": set(),
        "allowed_tools_by_agent": {},
        "required_scopes_by_tool": {},
    }

    allowed_tools = decoded.get("allowed_tools")
    if allowed_tools is not None:
        if not isinstance(allowed_tools, list) or not all(isinstance(item, str) and item for item in allowed_tools):
            raise ValueError("allowed_tools must be a non-empty string[]")
        result["allowed_tools"] = set(allowed_tools)

    allowed_by_agent = decoded.get("allowed_tools_by_agent")
    if allowed_by_agent is not None:
        if not isinstance(allowed_by_agent, dict):
            raise ValueError("allowed_tools_by_agent must be an object")
        parsed: dict[str, set[str]] = {}
        for agent_id, tools in allowed_by_agent.items():
            if not isinstance(agent_id, str) or not agent_id:
                raise ValueError("allowed_tools_by_agent keys must be non-empty strings")
            if not isinstance(tools, list) or not all(isinstance(item, str) and item for item in tools):
                raise ValueError("allowed_tools_by_agent must map to non-empty string[]")
            parsed[agent_id] = set(tools)
        result["allowed_tools_by_agent"] = parsed

    scopes_by_tool = decoded.get("required_scopes_by_tool")
    if scopes_by_tool is not None:
        if not isinstance(scopes_by_tool, dict):
            raise ValueError("required_scopes_by_tool must be an object")
        parsed_scopes: dict[str, str] = {}
        for tool_name, scope in scopes_by_tool.items():
            if not isinstance(tool_name, str) or not tool_name:
                raise ValueError("required_scopes_by_tool keys must be non-empty strings")
            if not isinstance(scope, str) or not scope:
                raise ValueError("required_scopes_by_tool values must be non-empty strings")
            parsed_scopes[tool_name] = scope
        result["required_scopes_by_tool"] = parsed_scopes

    return result


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


def _load_trust_governance_policy(path: str) -> TrustGovernancePolicy:
    content = pathlib.Path(path).read_text(encoding="utf-8")
    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError(f"{path} must contain a JSON object")

    approver_keys_raw = decoded.get("approver_keys")
    if not isinstance(approver_keys_raw, dict) or not approver_keys_raw:
        raise ValueError("approver_keys must be a non-empty object")
    approver_keys: dict[str, str] = {}
    for approver, key in approver_keys_raw.items():
        if not isinstance(approver, str) or not approver:
            raise ValueError("approver_keys keys must be non-empty strings")
        if not isinstance(key, str) or not key:
            raise ValueError("approver_keys values must be non-empty strings")
        approver_keys[approver] = key

    threshold_raw = decoded.get("threshold", 1)
    if not isinstance(threshold_raw, int):
        raise ValueError("threshold must be an integer")
    policy = TrustGovernancePolicy(approver_keys=approver_keys, threshold=threshold_raw)
    policy.validate()
    return policy


def _close_replay_cache(replay_cache: ReplayCache | SQLiteReplayCache | RedisReplayCache | None) -> None:
    if replay_cache is None:
        return
    close_fn = getattr(replay_cache, "close", None)
    if callable(close_fn):
        close_fn()


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
