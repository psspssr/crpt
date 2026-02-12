"""Protocol/content-type versioning helpers and policy metadata."""

from __future__ import annotations

from dataclasses import dataclass
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
    }


def enforce_capability_version_compatibility(
    cap: Any,
    *,
    local_version: int = PROTOCOL_VERSION,
) -> None:
    """Validate peer capability version metadata when present."""
    if not isinstance(cap, dict):
        return

    a2a = cap.get("a2a_sdl")
    if not isinstance(a2a, dict):
        return

    peer_version = a2a.get("v")
    if peer_version is None:
        return
    if not isinstance(peer_version, int):
        raise ValueError("cap.a2a_sdl.v must be an integer")
    if not is_protocol_version_compatible(peer_version, local_version=local_version):
        raise ValueError(
            f"incompatible capability protocol version: peer={peer_version} local={local_version}"
        )
