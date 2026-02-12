"""Tamper-evident audit chain with optional signing."""

from __future__ import annotations

import json
import ssl
import threading
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .utils import b64url_decode, b64url_encode, canonical_json_bytes, now_iso_utc, sha256_prefixed


class AuditError(ValueError):
    """Raised when audit chain is invalid."""


class AuditAnchor(Protocol):
    """External immutable sink integration for audit entry hashes."""

    def publish(self, *, entry_hash: str, entry: dict[str, Any]) -> None:
        """Publish audit entry hash and metadata."""


class HTTPAuditAnchor:
    """POST-based anchor publisher for external transparency/append-only services."""

    def __init__(
        self,
        url: str,
        *,
        timeout_s: float = 5.0,
        token: str | None = None,
        tls_ca_file: str | None = None,
        tls_client_cert_file: str | None = None,
        tls_client_key_file: str | None = None,
        tls_insecure_skip_verify: bool = False,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_s
        self.token = token
        self.tls_ca_file = tls_ca_file
        self.tls_client_cert_file = tls_client_cert_file
        self.tls_client_key_file = tls_client_key_file
        self.tls_insecure_skip_verify = tls_insecure_skip_verify

    def publish(self, *, entry_hash: str, entry: dict[str, Any]) -> None:
        payload = {
            "entry_hash": entry_hash,
            "entry": entry,
        }
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")

        context = _build_anchor_ssl_context(
            url=self.url,
            tls_ca_file=self.tls_ca_file,
            tls_client_cert_file=self.tls_client_cert_file,
            tls_client_key_file=self.tls_client_key_file,
            tls_insecure_skip_verify=self.tls_insecure_skip_verify,
        )
        if context is None:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:  # nosec B310
                response.read()
            return

        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        with opener.open(request, timeout=self.timeout_s) as response:  # nosec B310
            response.read()


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(
        self,
        path: str | Path,
        signing_private_key: str | None = None,
        signing_kid: str | None = None,
        anchor: AuditAnchor | None = None,
        anchor_fail_closed: bool = False,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._signing_key = _load_signing_private_key(signing_private_key)
        self._signing_kid = signing_kid
        self._anchor = anchor
        self._anchor_fail_closed = anchor_fail_closed
        self._last_hash = self._read_last_hash()

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry_base = {
                "ts": now_iso_utc(),
                "event": event,
                "prev_hash": self._last_hash,
            }
            entry_hash = sha256_prefixed(canonical_json_bytes(entry_base))
            entry = dict(entry_base)
            entry["entry_hash"] = entry_hash

            if self._signing_key is not None:
                signature = self._signing_key.sign(canonical_json_bytes(entry))
                sig_entry = {"alg": "ed25519", "value": b64url_encode(signature)}
                if self._signing_kid:
                    sig_entry["kid"] = self._signing_kid
                entry["sig"] = sig_entry

            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

            self._last_hash = entry_hash
            receipt: dict[str, Any] = {
                "entry_hash": entry_hash,
                "prev_hash": entry_base["prev_hash"],
            }
            if "sig" in entry:
                receipt["sig"] = entry["sig"]

            if self._anchor is not None:
                try:
                    self._anchor.publish(entry_hash=entry_hash, entry=entry)
                    receipt["anchor"] = {"status": "anchored"}
                except Exception as exc:
                    receipt["anchor"] = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
                    if self._anchor_fail_closed:
                        raise AuditError(f"audit anchor publish failed: {exc}") from exc
            return receipt

    def _read_last_hash(self) -> str | None:
        if not self.path.exists():
            return None

        last_line = ""
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line

        if not last_line:
            return None

        try:
            decoded = json.loads(last_line)
        except json.JSONDecodeError as exc:  # pragma: no cover
            raise AuditError("invalid audit log JSON line") from exc

        entry_hash = decoded.get("entry_hash")
        if not isinstance(entry_hash, str) or not entry_hash.startswith("sha256:"):
            raise AuditError("invalid audit log entry_hash")
        return entry_hash



def verify_audit_chain(
    path: str | Path,
    *,
    signing_public_key: str | None = None,
    require_signatures: bool = False,
) -> None:
    file_path = Path(path)
    if not file_path.exists():
        return

    verify_key = _load_signing_public_key(signing_public_key)
    prev_hash: str | None = None
    with file_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue

            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditError(f"line {line_no}: invalid JSON") from exc

            entry_hash = entry.get("entry_hash")
            if not isinstance(entry_hash, str) or not entry_hash.startswith("sha256:"):
                raise AuditError(f"line {line_no}: missing entry_hash")

            if entry.get("prev_hash") != prev_hash:
                raise AuditError(f"line {line_no}: prev_hash mismatch")

            base = {
                "ts": entry.get("ts"),
                "event": entry.get("event"),
                "prev_hash": entry.get("prev_hash"),
            }
            expected_hash = sha256_prefixed(canonical_json_bytes(base))
            if expected_hash != entry_hash:
                raise AuditError(f"line {line_no}: entry hash mismatch")

            sig = entry.get("sig")
            if require_signatures and not isinstance(sig, dict):
                raise AuditError(f"line {line_no}: missing signature")
            if isinstance(sig, dict):
                if sig.get("alg") != "ed25519":
                    raise AuditError(f"line {line_no}: unsupported sig alg")
                value = sig.get("value")
                if not isinstance(value, str) or not value:
                    raise AuditError(f"line {line_no}: invalid signature value")
                if verify_key is None:
                    raise AuditError(f"line {line_no}: signing_public_key required for signature verification")

                signed_doc = dict(entry)
                signed_doc.pop("sig", None)
                try:
                    verify_key.verify(b64url_decode(value), canonical_json_bytes(signed_doc))
                except (InvalidSignature, ValueError) as exc:
                    raise AuditError(f"line {line_no}: signature verification failed") from exc

            prev_hash = entry_hash



def _load_signing_private_key(value: str | None) -> Ed25519PrivateKey | None:
    if value is None:
        return None

    text = value.strip()
    if not text:
        return None

    if text.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(text.encode("ascii"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise AuditError("audit signing key is not Ed25519")
        return loaded

    raise AuditError("audit signing key must be PEM")


def _load_signing_public_key(value: str | None) -> Ed25519PublicKey | None:
    if value is None:
        return None

    text = value.strip()
    if not text:
        return None

    if text.startswith("-----BEGIN"):
        loaded = serialization.load_pem_public_key(text.encode("ascii"))
        if not isinstance(loaded, Ed25519PublicKey):
            raise AuditError("audit signing public key is not Ed25519")
        return loaded

    try:
        raw = b64url_decode(text)
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise AuditError("audit signing public key must be PEM or b64 raw") from exc


def _build_anchor_ssl_context(
    *,
    url: str,
    tls_ca_file: str | None,
    tls_client_cert_file: str | None,
    tls_client_key_file: str | None,
    tls_insecure_skip_verify: bool,
) -> ssl.SSLContext | None:
    lower_url = url.lower()
    if lower_url.startswith("http://"):
        if tls_ca_file or tls_client_cert_file or tls_client_key_file or tls_insecure_skip_verify:
            raise AuditError("audit anchor TLS options require an https:// URL")
        return None
    if not lower_url.startswith("https://"):
        raise AuditError("audit anchor URL scheme must be http or https")

    if bool(tls_client_cert_file) != bool(tls_client_key_file):
        raise AuditError("audit anchor client cert/key must be provided together")

    context = ssl.create_default_context(cafile=tls_ca_file)
    if tls_insecure_skip_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if tls_client_cert_file and tls_client_key_file:
        context.load_cert_chain(certfile=tls_client_cert_file, keyfile=tls_client_key_file)
    return context
