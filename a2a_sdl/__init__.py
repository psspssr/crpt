"""A2A-SDL reference implementation."""

from .envelope import (
    EnvelopeValidationError,
    build_envelope,
    derive_response_trace,
    make_error_response,
    validate_envelope,
)
from .codec import decode_bytes, encode_bytes
from .transport_http import send_http_with_auto_downgrade
from .transport_ipc import IPCServer, send_ipc
from .swarm import CodexBuddyServer, SwarmCoordinator
from .audit import AuditChain, verify_audit_chain
from .policy import SecurityPolicy
from .security import (
    decrypt_payload,
    encrypt_payload,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_envelope,
    verify_envelope_signature,
)

__all__ = [
    "EnvelopeValidationError",
    "build_envelope",
    "derive_response_trace",
    "make_error_response",
    "validate_envelope",
    "decode_bytes",
    "encode_bytes",
    "send_http_with_auto_downgrade",
    "send_ipc",
    "IPCServer",
    "CodexBuddyServer",
    "SwarmCoordinator",
    "AuditChain",
    "verify_audit_chain",
    "SecurityPolicy",
    "decrypt_payload",
    "encrypt_payload",
    "generate_signing_keypair",
    "generate_x25519_keypair",
    "sign_envelope",
    "verify_envelope_signature",
]

__version__ = "0.1.0"
