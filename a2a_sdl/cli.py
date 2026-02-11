"""CLI entrypoint for A2A-SDL."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any

from .audit import AuditChain
from .codec import decode_bytes, encode_bytes
from .envelope import build_envelope, validate_envelope
from .handlers import default_handler
from .policy import SecurityPolicy
from .schema import get_builtin_descriptor
from .security import (
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
)
from .replay import ReplayCache
from .swarm import BuddyEndpoint, CodexBackend, CodexBuddyServer, SwarmCoordinator
from .transport_http import A2AHTTPServer, send_http, send_http_with_auto_downgrade
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
    serve.add_argument("--replay-protection", action="store_true", help="Enable sec.replay nonce cache checks")
    serve.add_argument("--replay-ttl", type=int, default=600, help="Replay nonce TTL in seconds")
    serve.add_argument("--replay-max-entries", type=int, default=10000, help="Replay cache max entries")
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
    serve.add_argument("--audit-log-file", help="Append-only audit log path")
    serve.add_argument("--audit-signing-key", help="Ed25519 private key path for signing audit entries")
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
    replay_cache = None
    secure_policy_enabled = bool(
        args.secure_required
        or args.trusted_signing_keys_file
        or args.agent_kid_map_file
        or args.decrypt_keys_file
        or args.allowed_agent
    )

    if args.replay_protection or secure_policy_enabled:
        replay_cache = ReplayCache(max_entries=args.replay_max_entries, ttl_seconds=args.replay_ttl)

    security_policy = None
    if secure_policy_enabled:
        try:
            trusted_signing_keys = (
                _load_json_map(args.trusted_signing_keys_file) if args.trusted_signing_keys_file else {}
            )
            required_kid_by_agent = _load_json_map(args.agent_kid_map_file) if args.agent_kid_map_file else {}
            decrypt_private_keys = _load_json_map(args.decrypt_keys_file) if args.decrypt_keys_file else {}
        except Exception as exc:
            print(f"failed to load secure policy files: {exc}", file=sys.stderr)
            return 2

        if args.secure_required and (not trusted_signing_keys or not decrypt_private_keys):
            print(
                "--secure-required needs --trusted-signing-keys-file and --decrypt-keys-file",
                file=sys.stderr,
            )
            return 2

        security_policy = SecurityPolicy(
            require_mode="enc+sig" if args.secure_required else None,
            require_replay=args.secure_required,
            allowed_agents=set(args.allowed_agent),
            trusted_signing_keys=trusted_signing_keys,
            required_kid_by_agent=required_kid_by_agent,
            decrypt_private_keys=decrypt_private_keys,
        )

    audit_chain = None
    if args.audit_log_file:
        try:
            signing_key = _load_key_material(args.audit_signing_key) if args.audit_signing_key else None
            audit_chain = AuditChain(args.audit_log_file, signing_private_key=signing_key)
        except Exception as exc:
            print(f"failed to initialize audit chain: {exc}", file=sys.stderr)
            return 2

    server = A2AHTTPServer(
        args.host,
        args.port,
        handler=default_handler,
        replay_cache=replay_cache,
        enforce_replay=args.replay_protection,
        security_policy=security_policy,
        audit_chain=audit_chain,
    )
    print(f"serving on http://{args.host}:{args.port}/a2a")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
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
