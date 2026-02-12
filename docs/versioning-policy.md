# Versioning And Migration Policy

## SemVer Policy

- Project release versions follow SemVer: `MAJOR.MINOR.PATCH`.
- `MAJOR` changes may include protocol-breaking behavior.
- `MINOR` changes are backward-compatible feature additions.
- `PATCH` changes are backward-compatible bug/security fixes.

## Protocol Compatibility Rules

- Current protocol version is `v=1`.
- Peers must match the same protocol major version.
- Runtime validation enforces `cap.a2a_sdl.v` compatibility when capability metadata is present.
- New content types should use `name.vN` naming.
- A new content-type major (`task.v2`) requires explicit migration notes before rollout.

## Deprecation And Migration Requirements

- Breaking changes require a minimum **90-day deprecation window**.
- Every breaking release must include:
  - migration guidance from old to new message shapes,
  - rollback strategy,
  - compatibility matrix listing supported old/new versions.
- Negotiation responses should advertise versioning metadata to support gradual migration.

## Key Rotation/Revocation Policy

- Rotation is supported with `allowed_kids_by_agent` (multiple active kids).
- Revocation is immediate with `revoked_kids`.
- Expiring keys must be listed in `kid_not_after` and removed/replaced before expiry.
