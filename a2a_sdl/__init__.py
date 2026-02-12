"""A2A-SDL reference implementation."""

from .envelope import (
    EnvelopeValidationError,
    build_envelope,
    derive_response_trace,
    make_error_response,
    validate_envelope,
)
from .handlers import TrustGovernancePolicy
from .codec import decode_bytes, encode_bytes
from .conformance import render_conformance_json, render_conformance_text, run_conformance_suite
from .transport_http import send_http_with_auto_downgrade
from .transport_ipc import IPCServer, send_ipc
from .swarm import CodexBuddyServer, SwarmCoordinator
from .audit import AuditChain, HTTPAuditAnchor, verify_audit_chain
from .policy import SecurityPolicy, SecurityPolicyManager
from .session import SessionBindingRecord, SessionBindingStore, build_session_binding_doc, compute_session_binding_id
from .security import (
    decrypt_payload,
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
    verify_envelope_signature,
)
from .versioning import (
    RuntimeVersionPolicy,
    enforce_capability_version_compatibility,
    enforce_content_type_version_policy,
    is_protocol_version_compatible,
    parse_content_type_version,
    parse_runtime_version_policy,
    versioning_payload_metadata,
)

__all__ = [
    "EnvelopeValidationError",
    "build_envelope",
    "derive_response_trace",
    "make_error_response",
    "validate_envelope",
    "TrustGovernancePolicy",
    "decode_bytes",
    "encode_bytes",
    "run_conformance_suite",
    "render_conformance_text",
    "render_conformance_json",
    "send_http_with_auto_downgrade",
    "send_ipc",
    "IPCServer",
    "CodexBuddyServer",
    "SwarmCoordinator",
    "AuditChain",
    "HTTPAuditAnchor",
    "verify_audit_chain",
    "SecurityPolicy",
    "SecurityPolicyManager",
    "SessionBindingRecord",
    "SessionBindingStore",
    "build_session_binding_doc",
    "compute_session_binding_id",
    "RuntimeVersionPolicy",
    "decrypt_payload",
    "encrypt_payload",
    "generate_signing_keypair",
    "generate_x25519_keypair",
    "sign_envelope",
    "verify_envelope_signature",
    "parse_content_type_version",
    "parse_runtime_version_policy",
    "is_protocol_version_compatible",
    "enforce_capability_version_compatibility",
    "enforce_content_type_version_policy",
    "versioning_payload_metadata",
]

__version__ = "0.2.0"
