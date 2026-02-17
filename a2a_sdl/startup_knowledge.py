"""Built-in startup knowledge for installed A2A-SDL agents."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .utils import json_dumps_pretty

_STARTUP_KNOWLEDGE: dict[str, Any] = {
    "project": {
        "name": "A2A-SDL",
        "package": "a2acrpt",
        "protocol_version": "v1",
        "python": ">=3.11",
        "summary": (
            "Production-oriented reference implementation of a self-describing "
            "agent-to-agent protocol with strict envelope validation and optional "
            "cryptographic security."
        ),
    },
    "install": {
        "default_profile": "full",
        "recommended": [
            "uv tool install --upgrade a2acrpt",
            "uv tool update-shell",
        ],
        "alternatives": [
            "pipx install a2acrpt",
            "pip install a2acrpt",
        ],
    },
    "commands": [
        {"name": "a2a serve", "purpose": "Run local or production HTTP A2A server."},
        {"name": "a2a send", "purpose": "Send one request envelope to an A2A endpoint."},
        {"name": "a2a gateway", "purpose": "Run session-aware edge gateway in front of upstream agents."},
        {"name": "a2a workflow", "purpose": "Execute DAG workflow plans over A2A endpoints."},
        {"name": "a2a conformance", "purpose": "Run protocol conformance suite."},
        {"name": "a2a vectors", "purpose": "Generate canonical interoperability vectors."},
        {"name": "a2a knowledge", "purpose": "Print this built-in startup context."},
    ],
    "security_baseline": [
        "Use --deployment-mode prod for internet-facing deployments.",
        "Enable --secure-required and trusted signing/decryption key registries.",
        "Use durable replay storage (--replay-db-file or --replay-redis-url).",
        "Enable TLS (and mTLS where needed).",
        "Protect admin endpoints with --admin-token.",
    ],
    "docs": {
        "wire_spec": "docs/protocol-v1.md",
        "operations": "docs/operations-hardening.md",
        "versioning": "docs/versioning-policy.md",
        "interop_vectors": "docs/interop-vectors",
    },
}


def get_startup_knowledge() -> dict[str, Any]:
    """Return a copy of built-in startup context for installed runtimes."""
    return deepcopy(_STARTUP_KNOWLEDGE)


def render_startup_knowledge_text() -> str:
    """Render startup context as human-readable text."""
    data = get_startup_knowledge()
    lines: list[str] = []

    project = data["project"]
    lines.append(f"{project['name']} startup knowledge")
    lines.append("")
    lines.append(project["summary"])
    lines.append("")
    lines.append("Install (default full profile):")
    for command in data["install"]["recommended"]:
        lines.append(f"  - {command}")
    lines.append("")
    lines.append("Core commands:")
    for item in data["commands"]:
        lines.append(f"  - {item['name']}: {item['purpose']}")
    lines.append("")
    lines.append("Production security baseline:")
    for rule in data["security_baseline"]:
        lines.append(f"  - {rule}")
    lines.append("")
    lines.append("Built-in docs:")
    docs = data["docs"]
    lines.append(f"  - Wire spec: {docs['wire_spec']}")
    lines.append(f"  - Operations: {docs['operations']}")
    lines.append(f"  - Versioning: {docs['versioning']}")
    lines.append(f"  - Interop vectors: {docs['interop_vectors']}")
    return "\n".join(lines)


def render_startup_knowledge_json() -> str:
    """Render startup context as pretty JSON."""
    return json_dumps_pretty(get_startup_knowledge())
