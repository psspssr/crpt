"""Security policy enforcement for inbound envelopes."""

from __future__ import annotations

import datetime as dt
import threading
from dataclasses import dataclass, field
from typing import Any

from .envelope import EnvelopeValidationError
from .replay import ReplayCacheProtocol
from .schema import SchemaValidationError, validate_payload
from .security import SecurityError, decrypt_payload, verify_envelope_signature
from .utils import canonical_json_bytes, now_iso_utc, sha256_prefixed


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


@dataclass(slots=True)
class SecurityPolicyManager:
    """Thread-safe mutable registry view for dynamic trust sync."""

    policy: SecurityPolicy
    _updated_at: str = field(default_factory=now_iso_utc, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def snapshot(self, *, include_private: bool = False) -> dict[str, Any]:
        with self._lock:
            data: dict[str, Any] = {
                "trusted_signing_keys": dict(sorted(self.policy.trusted_signing_keys.items())),
                "required_kid_by_agent": dict(sorted(self.policy.required_kid_by_agent.items())),
                "allowed_kids_by_agent": {
                    key: sorted(values) for key, values in sorted(self.policy.allowed_kids_by_agent.items())
                },
                "revoked_kids": sorted(self.policy.revoked_kids),
                "kid_not_after": dict(sorted(self.policy.kid_not_after.items())),
                "updated_at": self._updated_at,
            }
            if include_private:
                data["decrypt_private_keys"] = dict(sorted(self.policy.decrypt_private_keys.items()))
            return data

    def snapshot_hash(self, *, include_private: bool = False) -> str:
        snap = self.snapshot(include_private=include_private)
        return sha256_prefixed(canonical_json_bytes(snap))

    def apply_registry(self, registry: dict[str, Any], *, merge: bool = True) -> str:
        normalized = _normalize_registry_payload(registry)
        with self._lock:
            if merge:
                self.policy.trusted_signing_keys.update(normalized["trusted_signing_keys"])
                self.policy.required_kid_by_agent.update(normalized["required_kid_by_agent"])
                for agent_id, kids in normalized["allowed_kids_by_agent"].items():
                    existing = self.policy.allowed_kids_by_agent.get(agent_id, set())
                    self.policy.allowed_kids_by_agent[agent_id] = set(existing) | set(kids)
                self.policy.revoked_kids.update(normalized["revoked_kids"])
                self.policy.kid_not_after.update(normalized["kid_not_after"])
                self.policy.decrypt_private_keys.update(normalized["decrypt_private_keys"])
            else:
                self.policy.trusted_signing_keys = dict(normalized["trusted_signing_keys"])
                self.policy.required_kid_by_agent = dict(normalized["required_kid_by_agent"])
                self.policy.allowed_kids_by_agent = {
                    key: set(values) for key, values in normalized["allowed_kids_by_agent"].items()
                }
                self.policy.revoked_kids = set(normalized["revoked_kids"])
                self.policy.kid_not_after = dict(normalized["kid_not_after"])
                self.policy.decrypt_private_keys = dict(normalized["decrypt_private_keys"])
            self._updated_at = now_iso_utc()
        return self.snapshot_hash(include_private=False)



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


def _normalize_registry_payload(registry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(registry, dict):
        raise ValueError("registry must be an object")

    trusted = _normalize_str_map(registry.get("trusted_signing_keys"), "trusted_signing_keys")
    required = _normalize_str_map(registry.get("required_kid_by_agent"), "required_kid_by_agent")
    kid_not_after = _normalize_str_map(registry.get("kid_not_after"), "kid_not_after")
    decrypt = _normalize_str_map(registry.get("decrypt_private_keys"), "decrypt_private_keys")
    allowed = _normalize_str_map_of_sets(registry.get("allowed_kids_by_agent"), "allowed_kids_by_agent")
    revoked = _normalize_str_set(registry.get("revoked_kids"), "revoked_kids")

    for kid, raw in kid_not_after.items():
        _parse_iso_utc(raw)

    return {
        "trusted_signing_keys": trusted,
        "required_kid_by_agent": required,
        "allowed_kids_by_agent": allowed,
        "revoked_kids": revoked,
        "kid_not_after": kid_not_after,
        "decrypt_private_keys": decrypt,
    }


def _normalize_str_map(raw: Any, field_name: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field_name} must be an object")
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{field_name} keys must be non-empty strings")
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field_name}.{key} must be a non-empty string")
        out[key] = value
    return out


def _normalize_str_map_of_sets(raw: Any, field_name: str) -> dict[str, set[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field_name} must be an object")
    out: dict[str, set[str]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"{field_name} keys must be non-empty strings")
        if not isinstance(value, list):
            raise ValueError(f"{field_name}.{key} must be a list")
        normalized: set[str] = set()
        for item in value:
            if not isinstance(item, str) or not item:
                raise ValueError(f"{field_name}.{key} entries must be non-empty strings")
            normalized.add(item)
        out[key] = normalized
    return out


def _normalize_str_set(raw: Any, field_name: str) -> set[str]:
    if raw is None:
        return set()
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a list")
    out: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{field_name} entries must be non-empty strings")
        out.add(item)
    return out
