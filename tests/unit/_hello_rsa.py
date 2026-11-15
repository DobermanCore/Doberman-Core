"""Software RSA for tests only (ADR 0119 slice 3): key generation, SubjectPublicKeyInfo DER
and RSASSA-PKCS1-v1_5 SHA-256 signing, standing in for a Windows Hello key on Linux CI.

Doberman itself never signs; it only verifies (``doberman.auth.hello_proof``).
"""

import hashlib
import math
import secrets
from dataclasses import dataclass
from functools import lru_cache

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p**0.5) + 1, 2))]
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _probably_prime(n: int) -> bool:
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(32):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if _probably_prime(candidate):
            return candidate


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _der_int(value: int) -> bytes:
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def spki(n: int, e: int) -> bytes:
    """An X.509 SubjectPublicKeyInfo for an RSA key (what KeyCredential returns)."""
    algorithm = _der(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    return _der(0x30, algorithm + _der(0x03, b"\x00" + _der(0x30, _der_int(n) + _der_int(e))))


@dataclass(frozen=True)
class SoftKey:
    n: int
    e: int
    d: int

    @property
    def public_key(self) -> bytes:
        return spki(self.n, self.e)

    def sign(self, data: bytes) -> bytes:
        k = (self.n.bit_length() + 7) // 8
        t = _SHA256_DIGESTINFO + hashlib.sha256(data).digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(k, "big")


@lru_cache(maxsize=None)
def keypair(label: str = "a", bits: int = 2048) -> SoftKey:
    """One cached key per label, so tests can hold a right key and a wrong one."""
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1 and (p * q).bit_length() == bits:
            return SoftKey(p * q, e, pow(e, -1, phi))
