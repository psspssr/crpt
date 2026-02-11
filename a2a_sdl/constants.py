"""Protocol constants."""

PROTOCOL_VERSION = 1
SUPPORTED_MESSAGE_TYPES = {"req", "res", "evt"}
SUPPORTED_CONTENT_TYPES = {
    "task.v1",
    "toolcall.v1",
    "toolresult.v1",
    "state.v1",
    "artifact.v1",
    "error.v1",
    "negotiation.v1",
}

DEFAULT_LIMITS = {
    "max_bytes": 1_048_576,
    "max_depth": 64,
    "max_array_len": 10_000,
    "max_hops": 8,
}

SUPPORTED_SECURITY_MODES = {"none", "sig", "enc", "enc+sig"}
SUPPORTED_SIG_ALGS = {"ed25519"}
SUPPORTED_ENC_ALGS = {"x25519-chacha20poly1305"}

ERROR_CODES = {
    "UNSUPPORTED_ENCODING",
    "UNSUPPORTED_CT",
    "SCHEMA_INVALID",
    "SECURITY_UNSUPPORTED",
    "BAD_REQUEST",
    "INTERNAL",
}
