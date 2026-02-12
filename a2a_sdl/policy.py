"""Security policy enforcement for inbound envelopes."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from .envelope import EnvelopeValidationError
from .replay import ReplayCacheProtocol
from .schema import SchemaValidationError, validate_payload
from .security import SecurityError, decrypt_payload, verify_envelope_signature


@dataclass(slots=True)
class SecurityPolicy:
    """Inbound policy for authentication and cryptographic enforcement."""

    require_mode: str | None = None
    require_replay: bool = False
    allowed_agents: set[str] = field(default_factory=set)
    trusted_signing_keys: dict[str, str] = field(default_factory=dict)
    required_kid_by_agent: dict[str, str] = field(default_factory=dict)
    allowed_kids_by_agent: dict[str, set[str]] = field(default_factory=dict)
    revoked_kids: set[str] = field(default_factory=set)
    kid_not_after: dict[str, str] = field(default_factory=dict)
    decrypt_private_keys: dict[str, str] = field(default_factory=dict)



def enforce_request_security(
    envelope: dict[str, Any],
    policy: SecurityPolicy,
    replay_cache: ReplayCacheProtocol | None,
) -> None:
    sec = envelope.get("sec")
    if not isinstance(sec, dict):
        raise EnvelopeValidationError("security policy requires sec block")

    mode = sec.get("mode")
    if policy.require_mode is not None and mode != policy.require_mode:
        raise EnvelopeValidationError(f"security policy requires mode {policy.require_mode}")

    from_identity = envelope.get("from")
    agent_id = ""
    if isinstance(from_identity, dict):
        raw = from_identity.get("agent_id")
        if isinstance(raw, str):
            agent_id = raw

    if policy.allowed_agents and agent_id not in policy.allowed_agents:
        raise EnvelopeValidationError("security policy rejects agent_id")

    kid = sec.get("kid")
    if not isinstance(kid, str) or not kid:
        raise EnvelopeValidationError("security policy requires sec.kid")

    if kid in policy.revoked_kids:
        raise EnvelopeValidationError("security policy rejects revoked sec.kid")

    kid_expiry_raw = policy.kid_not_after.get(kid)
    if kid_expiry_raw is not None:
        kid_expiry = _parse_iso_utc(kid_expiry_raw)
        if kid_expiry <= dt.datetime.now(dt.timezone.utc):
            raise EnvelopeValidationError("security policy rejects expired sec.kid")

    expected_kid = policy.required_kid_by_agent.get(agent_id)
    if expected_kid is not None and kid != expected_kid:
        raise EnvelopeValidationError("security policy rejects sec.kid for agent")

    allowed_kids = policy.allowed_kids_by_agent.get(agent_id)
    if allowed_kids is not None and kid not in allowed_kids:
        raise EnvelopeValidationError("security policy rejects sec.kid not in allowed rotation set")

    public_key = policy.trusted_signing_keys.get(kid)
    if public_key is None:
        raise EnvelopeValidationError("security policy does not trust sec.kid")

    try:
        verify_envelope_signature(envelope, public_key)
    except SecurityError as exc:
        raise EnvelopeValidationError(f"signature verification failed: {exc}") from exc

    if policy.require_replay:
        _enforce_replay(envelope, replay_cache)

    if mode in {"enc", "enc+sig"}:
        _decrypt_payload(envelope, policy)

    try:
        validate_payload(envelope.get("payload"), envelope["schema"])
    except SchemaValidationError as exc:
        raise EnvelopeValidationError(f"payload validation failed: {exc}") from exc



def _enforce_replay(envelope: dict[str, Any], replay_cache: ReplayCacheProtocol | None) -> None:
    if replay_cache is None:
        raise EnvelopeValidationError("security policy requires replay cache")

    sec = envelope.get("sec")
    if not isinstance(sec, dict):
        raise EnvelopeValidationError("security policy requires sec block")

    replay = sec.get("replay")
    if not isinstance(replay, dict):
        raise EnvelopeValidationError("security policy requires sec.replay")

    nonce = replay.get("nonce")
    exp = replay.get("exp")
    if not isinstance(nonce, str) or not nonce:
        raise EnvelopeValidationError("sec.replay.nonce must be a non-empty string")
    if not isinstance(exp, str):
        raise EnvelopeValidationError("sec.replay.exp must be a string")

    exp_ts = _parse_iso_utc(exp)
    now = dt.datetime.now(dt.timezone.utc)
    if exp_ts <= now:
        raise EnvelopeValidationError("sec.replay expired")

    from_identity = envelope.get("from")
    if isinstance(from_identity, dict):
        agent_id = str(from_identity.get("agent_id", "did:key:unknown"))
    else:
        agent_id = "did:key:unknown"

    if replay_cache.seen_or_add(agent_id, nonce):
        raise EnvelopeValidationError("sec.replay nonce already seen")



def _decrypt_payload(envelope: dict[str, Any], policy: SecurityPolicy) -> None:
    sec = envelope.get("sec")
    if not isinstance(sec, dict):
        raise EnvelopeValidationError("security policy requires sec block")

    enc = sec.get("enc")
    if not isinstance(enc, dict):
        raise EnvelopeValidationError("security policy requires sec.enc block")

    recipients = enc.get("recipients")
    if not isinstance(recipients, list):
        raise EnvelopeValidationError("sec.enc.recipients must be an array")

    selected_kid: str | None = None
    for item in recipients:
        if not isinstance(item, dict):
            continue
        candidate = item.get("kid")
        if isinstance(candidate, str) and candidate in policy.decrypt_private_keys:
            selected_kid = candidate
            break

    if selected_kid is None:
        raise EnvelopeValidationError("security policy has no decrypt key for recipients")

    try:
        decrypt_payload(envelope, policy.decrypt_private_keys[selected_kid], kid=selected_kid)
    except SecurityError as exc:
        raise EnvelopeValidationError(f"decryption failed: {exc}") from exc


def _parse_iso_utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)
