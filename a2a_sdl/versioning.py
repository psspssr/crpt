"""Protocol/content-type versioning helpers and policy metadata."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from .constants import PROTOCOL_VERSION


@dataclass(frozen=True, slots=True)
class CompatibilityRule:
    """Rule describing compatibility expectations for the protocol."""

    protocol_semver: str
    requires_same_major: bool
    supports_minor_forward_compat: bool
    deprecation_window_days: int
    rollback_supported: bool


DEFAULT_COMPAT_RULE = CompatibilityRule(
    protocol_semver=f"{PROTOCOL_VERSION}.0.0",
    requires_same_major=True,
    supports_minor_forward_compat=True,
    deprecation_window_days=90,
    rollback_supported=True,
)


@dataclass(frozen=True, slots=True)
class RuntimeVersionPolicy:
    """Runtime policy for migration/deprecation enforcement."""

    min_peer_protocol: int | None = None
    max_peer_protocol: int | None = None
    require_peer_version: bool = False
    deprecated_content_types: dict[str, str] = field(default_factory=dict)
    allowed_content_type_versions: dict[str, tuple[int, int]] = field(default_factory=dict)


def parse_content_type_version(content_type: str) -> tuple[str, int] | None:
    """Parse `name.vN` format into base name and integer version."""
    if not isinstance(content_type, str):
        return None
    if ".v" not in content_type:
        return None
    base, version_str = content_type.rsplit(".v", 1)
    if not base or not version_str.isdigit():
        return None
    return base, int(version_str)


def is_protocol_version_compatible(peer_version: int, *, local_version: int = PROTOCOL_VERSION) -> bool:
    """Current policy: protocol major version must match exactly."""
    return int(peer_version) == int(local_version)


def parse_runtime_version_policy(raw: dict[str, Any]) -> RuntimeVersionPolicy:
    """Parse runtime migration policy from JSON-compatible mapping."""
    if not isinstance(raw, dict):
        raise ValueError("version policy must be an object")

    min_peer = raw.get("min_peer_protocol")
    max_peer = raw.get("max_peer_protocol")
    require_peer_raw = raw.get("require_peer_version", False)
    deprecated = raw.get("deprecated_content_types", {})
    ct_ranges_raw = raw.get("allowed_content_type_versions", {})

    if min_peer is not None and not isinstance(min_peer, int):
        raise ValueError("min_peer_protocol must be an integer")
    if max_peer is not None and not isinstance(max_peer, int):
        raise ValueError("max_peer_protocol must be an integer")
    if not isinstance(require_peer_raw, bool):
        raise ValueError("require_peer_version must be a boolean")
    if min_peer is not None and max_peer is not None and min_peer > max_peer:
        raise ValueError("min_peer_protocol cannot exceed max_peer_protocol")
    if not isinstance(deprecated, dict):
        raise ValueError("deprecated_content_types must be an object")
    if not isinstance(ct_ranges_raw, dict):
        raise ValueError("allowed_content_type_versions must be an object")

    deprecated_map: dict[str, str] = {}
    for content_type, deadline in deprecated.items():
        if not isinstance(content_type, str) or not content_type:
            raise ValueError("deprecated_content_types keys must be non-empty strings")
        if not isinstance(deadline, str):
            raise ValueError("deprecated_content_types values must be ISO timestamps")
        _parse_iso_utc(deadline)
        deprecated_map[content_type] = deadline

    ct_ranges: dict[str, tuple[int, int]] = {}
    for family, bounds in ct_ranges_raw.items():
        if not isinstance(family, str) or not family:
            raise ValueError("allowed_content_type_versions keys must be non-empty strings")
        if not isinstance(bounds, dict):
            raise ValueError("allowed_content_type_versions values must be objects")
        min_v = bounds.get("min")
        max_v = bounds.get("max")
        if not isinstance(min_v, int) or not isinstance(max_v, int):
            raise ValueError("allowed_content_type_versions entries require integer min/max")
        if min_v < 0 or max_v < 0 or min_v > max_v:
            raise ValueError("allowed_content_type_versions min/max must satisfy 0 <= min <= max")
        ct_ranges[family] = (min_v, max_v)

    require_peer = require_peer_raw
    return RuntimeVersionPolicy(
        min_peer_protocol=min_peer,
        max_peer_protocol=max_peer,
        require_peer_version=require_peer,
        deprecated_content_types=deprecated_map,
        allowed_content_type_versions=ct_ranges,
    )


def versioning_payload_metadata() -> dict[str, Any]:
    """Emit compatibility and migration metadata for negotiation responses."""
    return {
        "protocol": {
            "current": PROTOCOL_VERSION,
            "supported": [PROTOCOL_VERSION],
            "requires_same_major": DEFAULT_COMPAT_RULE.requires_same_major,
        },
        "semver_policy": {
            "version": DEFAULT_COMPAT_RULE.protocol_semver,
            "minor_forward_compat": DEFAULT_COMPAT_RULE.supports_minor_forward_compat,
        },
        "migration": {
            "deprecation_window_days": DEFAULT_COMPAT_RULE.deprecation_window_days,
            "requires_migration_metadata_for_breaking_changes": True,
            "rollback_supported": DEFAULT_COMPAT_RULE.rollback_supported,
        },
        "runtime_policy": {
            "supports_peer_min_max": True,
            "supports_content_type_deprecation": True,
            "supports_content_type_version_ranges": True,
        },
    }


def enforce_capability_version_compatibility(
    cap: Any,
    *,
    local_version: int = PROTOCOL_VERSION,
    runtime_policy: RuntimeVersionPolicy | None = None,
) -> None:
    """Validate peer capability version metadata when present."""
    if not isinstance(cap, dict):
        return

    a2a = cap.get("a2a_sdl")
    if not isinstance(a2a, dict):
        if runtime_policy is not None and runtime_policy.require_peer_version:
            raise ValueError("cap.a2a_sdl.v is required by runtime version policy")
        return

    peer_version = a2a.get("v")
    if peer_version is None:
        if runtime_policy is not None and runtime_policy.require_peer_version:
            raise ValueError("cap.a2a_sdl.v is required by runtime version policy")
        return
    if not isinstance(peer_version, int):
        raise ValueError("cap.a2a_sdl.v must be an integer")
    if runtime_policy is not None:
        if runtime_policy.min_peer_protocol is not None and peer_version < runtime_policy.min_peer_protocol:
            raise ValueError(
                f"peer capability protocol version {peer_version} is below required minimum "
                f"{runtime_policy.min_peer_protocol}"
            )
        if runtime_policy.max_peer_protocol is not None and peer_version > runtime_policy.max_peer_protocol:
            raise ValueError(
                f"peer capability protocol version {peer_version} is above allowed maximum "
                f"{runtime_policy.max_peer_protocol}"
            )
    if not is_protocol_version_compatible(peer_version, local_version=local_version):
        raise ValueError(
            f"incompatible capability protocol version: peer={peer_version} local={local_version}"
        )


def enforce_content_type_version_policy(
    content_type: str,
    *,
    runtime_policy: RuntimeVersionPolicy | None,
    now: dt.datetime | None = None,
) -> None:
    """Apply runtime migration rules for content-type deprecation/version ranges."""
    if runtime_policy is None:
        return

    deadline = runtime_policy.deprecated_content_types.get(content_type)
    if deadline is not None:
        ts = _parse_iso_utc(deadline)
        current = now.astimezone(dt.timezone.utc) if now is not None else dt.datetime.now(dt.timezone.utc)
        if current >= ts:
            raise ValueError(f"content type is deprecated and no longer accepted: {content_type}")

    parsed = parse_content_type_version(content_type)
    if parsed is None:
        return
    family, version = parsed
    allowed = runtime_policy.allowed_content_type_versions.get(family)
    if allowed is None:
        return
    min_v, max_v = allowed
    if version < min_v or version > max_v:
        raise ValueError(
            f"content type version {content_type} not in allowed range {family}.v{min_v}..{family}.v{max_v}"
        )


def _parse_iso_utc(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)
