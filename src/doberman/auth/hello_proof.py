"""Signed proof for Hello-required mode (ADR 0119, slice 3). Verify only; never signs.

A proof-tier approval in the mode is a signature by the ``doberman-proof`` Windows Hello key
over this exact ASCII message (each line ends in ``\\n``)::

    doberman-proof-v1
    action_id=<action id: 1-128 of [A-Za-z0-9._:-]>
    action_hash=<hmac:<64 hex> for an action, sha256:<64 hex> for a fixed label>
    signed_at=<unix seconds, made by the verifying process>
    nonce=<32 lowercase hex, fresh per challenge>

Every field is checked against a character set without ``\\n`` or ``=``, so the framing is
unambiguous. The first line separates these signatures from anything else the key signs.

The scheme is RSASSA-PKCS1-v1_5 with SHA-256 over a 2048-bit (or larger) RSA key, given as an
X.509 SubjectPublicKeyInfo: what ``KeyCredentialManager`` creates by default and
``KeyCredential.RetrievePublicKey`` returns. The standard library has no RSA, so
:func:`verify_signature` is a small, verify-only implementation that rebuilds the one
expected encoded block and compares it in constant time (it never parses the padding, which
is what signature-forgery bugs in PKCS#1 v1.5 verifiers came from).

The verifying process makes the nonce and timestamp itself and checks the signature against
the key pinned in the machine marker, so the code that produced the signature is not trusted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from doberman.models import SecurityObject

DOMAIN = "doberman-proof-v1"

#: Oldest proof accepted, in seconds. The signing child has DEFAULT_APPROVAL_TIMEOUT_S (300 s)
#: for the gesture; the rest is slack for starting it.
MAX_AGE_S = 330
#: How far in the future a timestamp may be (the same clock made it; this is rounding slack).
MAX_SKEW_S = 5
MIN_RSA_BITS = 2048

_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_HASH = re.compile(r"(hmac|sha256):[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_RSA_ALGORITHM = bytes.fromhex("06092a864886f70d010101") + b"\x05\x00"  # rsaEncryption, NULL
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")

#: Nonces and signatures this process has accepted. Each challenge has a fresh nonce, so a
#: replay cannot match a new message anyway; this refuses one outright.
_seen: set[object] = set()


@dataclass(frozen=True)
class Proof:
    """The signed fields, the signature, and (not signed) the pinned key's id."""

    action_id: str
    action_hash: str
    signed_at: int
    nonce: str
    signature: bytes = b""
    key_id: str = ""

    def message(self) -> bytes:
        """The exact bytes signed. Raises ``ValueError`` on a malformed field."""
        if not (
            isinstance(self.action_id, str)
            and _ID.fullmatch(self.action_id)
            and isinstance(self.action_hash, str)
            and _HASH.fullmatch(self.action_hash)
            and isinstance(self.nonce, str)
            and _NONCE.fullmatch(self.nonce)
            and type(self.signed_at) is int
            and self.signed_at >= 0
        ):
            raise ValueError("not a well-formed proof")
        return (
            f"{DOMAIN}\naction_id={self.action_id}\naction_hash={self.action_hash}\n"
            f"signed_at={self.signed_at}\nnonce={self.nonce}\n"
        ).encode("ascii")


def new_challenge(action_id: str, action_hash: str, *, now: float | None = None) -> Proof:
    """An unsigned proof with a fresh nonce and this process's clock."""
    when = int(time.time() if now is None else now)
    return Proof(action_id, action_hash, when, secrets.token_hex(16))


def action_hash(action: SecurityObject) -> str:
    """A keyed HMAC of the redacted action, so the stored hash reveals nothing about it."""
    from doberman.storage.fingerprint import fingerprint  # lazy: the auth stack loads first

    identity = {
        "id": action.id,
        "ts": action.ts.isoformat(),
        "role": action.agent_role,
        "type": action.action_type.value,
        "tool": action.tool_name,
        "target": action.target,
        "destination": action.external_destination,
        "args": action.raw_args_redacted,
        "fingerprint": action.action_fingerprint,
    }
    value = fingerprint(json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str))
    if not _HASH.fullmatch(value):
        raise ValueError("unexpected fingerprint format")
    return value


def label_hash(label: str) -> str:
    """For a fixed operation with no action object (a policy weakening, leaving the mode)."""
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def key_id(public_key: bytes) -> str:
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def _der(buf: bytes, pos: int, tag: int) -> tuple[bytes, int]:
    """One DER element with ``tag`` at ``pos``: ``(body, next_pos)``. Strict lengths."""
    if pos + 2 > len(buf) or buf[pos] != tag:
        raise ValueError("unexpected DER element")
    length, pos = buf[pos + 1], pos + 2
    if length & 0x80:
        size = length & 0x7F
        if not 1 <= size <= 4 or pos + size > len(buf) or buf[pos] == 0:
            raise ValueError("bad DER length")
        length, pos = int.from_bytes(buf[pos : pos + size], "big"), pos + size
        if length < 0x80:
            raise ValueError("non-minimal DER length")
    if pos + length > len(buf):
        raise ValueError("truncated DER element")
    return buf[pos : pos + length], pos + length


def _der_uint(body: bytes) -> int:
    if not body or body[0] & 0x80 or (len(body) > 1 and body[0] == 0 and not body[1] & 0x80):
        raise ValueError("not a minimal positive INTEGER")
    return int.from_bytes(body, "big")


def rsa_public_numbers(public_key: bytes) -> tuple[int, int]:
    """``(n, e)`` from an RSA SubjectPublicKeyInfo. Raises ``ValueError`` for anything else."""
    outer, end = _der(public_key, 0, 0x30)
    if end != len(public_key):
        raise ValueError("trailing bytes after the key")
    algorithm, pos = _der(outer, 0, 0x30)
    bits, pos = _der(outer, pos, 0x03)
    if pos != len(outer) or algorithm != _RSA_ALGORITHM or not bits or bits[0] != 0:
        raise ValueError("not an RSA public key")
    rsa_key, pos = _der(bits, 1, 0x30)
    if pos != len(bits):
        raise ValueError("trailing bytes in the key")
    n_body, pos = _der(rsa_key, 0, 0x02)
    e_body, pos = _der(rsa_key, pos, 0x02)
    if pos != len(rsa_key):
        raise ValueError("trailing bytes in the key")
    n, e = _der_uint(n_body), _der_uint(e_body)
    if n.bit_length() < MIN_RSA_BITS or e < 3 or e % 2 == 0 or e >= n:
        raise ValueError("RSA key too small or malformed")
    return n, e


def verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 SHA-256 verification. True only for a valid signature; never raises."""
    try:
        n, e = rsa_public_numbers(public_key)
        k = (n.bit_length() + 7) // 8
        if not isinstance(signature, bytes) or len(signature) != k:
            return False
        s = int.from_bytes(signature, "big")
        if s >= n:
            return False
        t = _SHA256_DIGESTINFO + hashlib.sha256(data).digest()
        expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return hmac.compare_digest(pow(s, e, n).to_bytes(k, "big"), expected)
    except Exception:  # noqa: BLE001 - a key or signature we cannot read never verifies
        return False


def accept(
    proof: Proof,
    *,
    action_id: str,
    action_hash: str,
    public_key: bytes,
    now: float | None = None,
) -> bool:
    """True only for a fresh, unreplayed proof of THIS action signed by ``public_key``.

    Wrong action id or hash, a timestamp older than :data:`MAX_AGE_S` or more than
    :data:`MAX_SKEW_S` ahead, a nonce or signature already accepted here, a signature that
    does not verify, or any error: False. An accepted proof's nonce and signature are spent.
    """
    try:
        current = time.time() if now is None else now
        age = current - proof.signed_at
        if (
            proof.action_id != action_id
            or proof.action_hash != action_hash
            or not -MAX_SKEW_S <= age <= MAX_AGE_S
            or proof.nonce in _seen
            or proof.signature in _seen
            or not verify_signature(public_key, proof.message(), proof.signature)
        ):
            return False
        _seen.update((proof.nonce, proof.signature))
        return True
    except Exception:  # noqa: BLE001 - anything unexpected is a refusal
        return False


def check_stored(proof: Proof, public_key: bytes) -> bool:
    """Re-check stored evidence later: does ``public_key`` sign exactly these fields?

    No freshness or replay check (the proof is old by design). Never raises.
    """
    try:
        return verify_signature(public_key, proof.message(), proof.signature)
    except Exception:  # noqa: BLE001
        return False
