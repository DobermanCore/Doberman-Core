"""Hello-required mode, signed proof (ADR 0119 slice 3).

A proof-tier approval in the mode is an RSA PKCS#1 v1.5 SHA-256 signature by the Hello key
over a canonical message naming the action, checked against the public key pinned in the
machine marker. Runs on Linux CI: a software RSA key (``tests/unit/_hello_rsa.py``) stands in
for the Hello key, and the PowerShell child is faked (test_hello_powershell.py).
"""

import asyncio
import base64
import dataclasses
import json

import pytest

from doberman.auth import hello_mode, hello_proof
from doberman.auth.challenge import AuthTier, run_auth_challenge
from doberman.auth.methods.windows_hello import HelloError
from doberman.auth.provider import LOCAL_PROVIDER, LocalAuthProvider
from doberman.policy import drift
from doberman.storage import hello_proofs
from doberman.storage.db import open_db
from tests.unit._hello_rsa import keypair
from tests.unit.test_auth_provider import _action
from tests.unit.test_auth_provider import _auth_decision as _decision

KEY = keypair("a")
OTHER = keypair("b")
_HASH = "hmac:" + "ab" * 32
_NOW = 1_800_000_000


@pytest.fixture(autouse=True)
def _fresh_replay_memory(monkeypatch):
    monkeypatch.setattr(hello_proof, "_seen", set())


def _signed(key=KEY, **fields):
    base = {"action_id": "act-1", "action_hash": _HASH, "signed_at": _NOW, "nonce": "0f" * 16}
    base.update(fields)
    proof = hello_proof.Proof(**base)
    return dataclasses.replace(proof, signature=key.sign(proof.message()))


def _accept(proof, *, key=KEY, action_id="act-1", action_hash=_HASH, now=_NOW + 1):
    return hello_proof.accept(
        proof, action_id=action_id, action_hash=action_hash, public_key=key.public_key, now=now
    )


# --- RSA PKCS#1 v1.5 SHA-256 verification ---------------------------------------------------


def test_a_good_signature_verifies():
    assert hello_proof.verify_signature(KEY.public_key, b"data", KEY.sign(b"data")) is True


@pytest.mark.parametrize(
    "case",
    ["wrong_key", "other_data", "flipped_bit", "short", "long", "zero", "at_modulus", "empty"],
)
def test_anything_but_the_right_signature_fails(case):
    sig = KEY.sign(b"data")
    k = len(sig)
    public_key, data = KEY.public_key, b"data"
    if case == "wrong_key":
        public_key = OTHER.public_key
    elif case == "other_data":
        data = b"datb"
    elif case == "flipped_bit":
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    elif case == "short":
        sig = sig[1:]
    elif case == "long":
        sig = b"\x00" + sig
    elif case == "zero":
        sig = bytes(k)
    elif case == "at_modulus":
        sig = KEY.n.to_bytes(k, "big")
    elif case == "empty":
        sig = b""
    assert hello_proof.verify_signature(public_key, data, sig) is False


def test_a_signature_with_a_different_hash_or_padding_fails():
    import hashlib

    k = (KEY.n.bit_length() + 7) // 8
    # SHA-1 DigestInfo, otherwise a well-formed PKCS#1 v1.5 block
    t = bytes.fromhex("3021300906052b0e03021a05000414") + hashlib.sha1(b"data").digest()  # noqa: S324
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), KEY.d, KEY.n).to_bytes(k, "big")
    assert hello_proof.verify_signature(KEY.public_key, b"data", sig) is False
    # garbage after the digest instead of padding before it (a Bleichenbacher '06 shape)
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(b"data").digest()
    em = b"\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00" + t
    em += b"\x00" * (k - len(em))
    sig = pow(int.from_bytes(em, "big"), KEY.d, KEY.n).to_bytes(k, "big")
    assert hello_proof.verify_signature(KEY.public_key, b"data", sig) is False
    # the right DigestInfo and digest at the end, but not the PKCS#1 v1.5 padding before it
    pad = k - len(t) - 3
    for head in (
        b"\x00\x01" + b"\xfe" * pad,
        b"\x00\x02" + b"\xff" * pad,
        b"\x00\x01" + bytes(pad),
    ):
        em = head + b"\x00" + t
        sig = pow(int.from_bytes(em, "big"), KEY.d, KEY.n).to_bytes(k, "big")
        assert hello_proof.verify_signature(KEY.public_key, b"data", sig) is False
    # and with the digest right but a different DigestInfo prefix in front of it
    em = b"\x00\x01" + b"\xff" * pad + b"\x00" + b"\x00" * 19 + hashlib.sha256(b"data").digest()
    sig = pow(int.from_bytes(em, "big"), KEY.d, KEY.n).to_bytes(k, "big")
    assert hello_proof.verify_signature(KEY.public_key, b"data", sig) is False


@pytest.mark.parametrize(
    "public_key",
    [
        b"",
        b"\x30\x59fake-spki-public-key",
        KEY.public_key[:-1],
        KEY.public_key + b"\x00",
        # an EC P-256 SubjectPublicKeyInfo header: not RSA
        bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + bytes(64),
    ],
)
def test_a_key_that_is_not_a_2048_bit_rsa_spki_never_verifies(public_key):
    assert hello_proof.verify_signature(public_key, b"data", KEY.sign(b"data")) is False


def test_a_short_rsa_key_is_refused():
    small = keypair("small", bits=1024)
    with pytest.raises(ValueError):
        hello_proof.rsa_public_numbers(small.public_key)
    assert hello_proof.verify_signature(small.public_key, b"d", small.sign(b"d")) is False


def test_the_verifier_agrees_with_an_independent_implementation():
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.padding")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sig = private.sign(b"message", crypto.PKCS1v15(), hashes.SHA256())
    assert hello_proof.verify_signature(spki, b"message", sig) is True
    assert hello_proof.verify_signature(spki, b"messagf", sig) is False
    assert hello_proof.rsa_public_numbers(spki) == (
        private.public_key().public_numbers().n,
        65537,
    )


# --- the canonical message -----------------------------------------------------------------


def test_the_message_format_is_pinned():
    proof = hello_proof.Proof("act-1", _HASH, _NOW, "0f" * 16)
    assert proof.message() == (
        b"doberman-proof-v1\n"
        b"action_id=act-1\n"
        b"action_hash=" + _HASH.encode() + b"\n"
        b"signed_at=1800000000\n"
        b"nonce=" + b"0f" * 16 + b"\n"
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"action_id": "a\nnonce=00"},
        {"action_id": ""},
        {"action_id": "x" * 129},
        {"action_hash": "md5:abc"},
        {"action_hash": _HASH + "\n"},
        {"nonce": "short"},
        {"nonce": "0F" * 16},
        {"signed_at": True},
        {"signed_at": -1},
        {"signed_at": "1800000000"},
    ],
)
def test_a_malformed_field_cannot_be_signed(fields):
    base = {"action_id": "act-1", "action_hash": _HASH, "signed_at": _NOW, "nonce": "0f" * 16}
    base.update(fields)
    with pytest.raises(ValueError):
        hello_proof.Proof(**base).message()


def test_challenges_get_fresh_nonces():
    a = hello_proof.new_challenge("act-1", _HASH, now=_NOW)
    b = hello_proof.new_challenge("act-1", _HASH, now=_NOW)
    assert a.nonce != b.nonce
    assert a.signed_at == _NOW
    a.message()


def test_the_action_hash_is_keyed_and_bound_to_the_action():
    action = _action()
    h = hello_proof.action_hash(action)
    assert h.startswith("hmac:")
    assert h == hello_proof.action_hash(action)
    assert h != hello_proof.action_hash(action.model_copy(update={"target": "/elsewhere"}))
    assert h != hello_proof.action_hash(action.model_copy(update={"id": "another-id"}))
    assert action.target not in h


def test_label_hash_is_well_formed():
    h = hello_proof.label_hash("this policy weakening")
    hello_proof.Proof("policy-weaken", h, _NOW, "0f" * 16).message()


# --- accept: binding, freshness, replay ----------------------------------------------------


def test_accept_takes_a_good_proof():
    assert _accept(_signed()) is True


def test_wrong_key_wrong_action_or_wrong_hash_is_refused():
    assert _accept(_signed(key=OTHER)) is False
    assert _accept(_signed(), action_id="act-2") is False
    assert _accept(_signed(), action_hash="hmac:" + "cd" * 32) is False


def test_a_signature_over_other_fields_is_refused():
    proof = _signed()
    forged = dataclasses.replace(proof, action_id="act-2")  # signature still covers act-1
    assert _accept(forged, action_id="act-2") is False


@pytest.mark.parametrize(
    "now", [_NOW + hello_proof.MAX_AGE_S + 1, _NOW - hello_proof.MAX_SKEW_S - 1]
)
def test_a_stale_or_future_timestamp_is_refused(now):
    assert _accept(_signed(), now=now) is False


def test_the_window_edges_are_accepted():
    assert _accept(_signed(), now=_NOW + hello_proof.MAX_AGE_S) is True
    assert _accept(_signed(nonce="1f" * 16), now=_NOW - hello_proof.MAX_SKEW_S) is True


def test_a_replayed_proof_is_refused():
    proof = _signed()
    assert _accept(proof) is True
    assert _accept(proof) is False
    # the same nonce again, even freshly signed with other fields
    assert _accept(_signed(action_id="act-2"), action_id="act-2") is False


def test_a_refused_proof_does_not_burn_its_nonce():
    proof = _signed()
    assert _accept(proof, action_id="act-2") is False
    assert _accept(proof) is True


def test_accept_never_raises():
    assert hello_proof.accept(None, action_id="a", action_hash=_HASH, public_key=b"") is False
    assert _accept(_signed(), key=keypair("small", bits=1024)) is False


def test_a_stored_proof_can_be_checked_later():
    proof = _signed()
    assert hello_proof.check_stored(proof, KEY.public_key) is True
    assert hello_proof.check_stored(proof, OTHER.public_key) is False
    assert (
        hello_proof.check_stored(dataclasses.replace(proof, nonce="1f" * 16), KEY.public_key)
        is False
    )


# --- hello_mode.prove: the pinned key decides -----------------------------------------------


class SigningBackend:
    """Signs with a software key, like the Hello key would (after a gesture)."""

    def __init__(self, key=KEY, *, raises=None, tamper=None):
        self.key, self.raises, self.tamper = key, raises, tamper
        self.signed: list[bytes] = []

    def sign(self, data, *, timeout_s=None):
        self.signed.append(data)
        if self.raises is not None:
            raise self.raises
        return self.key.sign(self.tamper(data) if self.tamper else data)

    def public_key(self):
        return self.key.public_key


def _marker_with(path, *keys):
    body = {
        "version": 1,
        "public_key": base64.b64encode(keys[0].public_key).decode(),
        "enrolled_at": "2026-11-14T00:00:00+00:00",
    }
    path.write_text(json.dumps(body), encoding="utf-8")


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / "proof.json"
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(path))
    _marker_with(path, KEY)
    return path


@pytest.fixture
def signer(monkeypatch):
    holder = {"b": SigningBackend()}
    monkeypatch.setattr(hello_mode, "backend", lambda: holder["b"])

    def _set(**kwargs):
        holder["b"] = SigningBackend(**kwargs)
        return holder["b"]

    _set.current = lambda: holder["b"]
    return _set


def test_prove_approves_a_signature_by_the_pinned_key(marker, signer):
    approved, method, proof = hello_mode.prove(action_id="act-1", action_hash=_HASH)
    assert (approved, method) == (True, "windows_hello")
    assert proof.action_id == "act-1" and proof.action_hash == _HASH
    assert proof.key_id == hello_proof.key_id(KEY.public_key)
    assert signer.current().signed == [proof.message()]
    assert hello_proof.check_stored(proof, KEY.public_key)


def test_prove_refuses_a_key_that_is_not_pinned(marker, signer):
    signer(key=OTHER)
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH) == (
        False,
        hello_mode.HELLO_REQUIRED_METHOD,
        None,
    )


def test_prove_refuses_a_signature_over_another_message(marker, signer):
    signer(tamper=lambda data: data.replace(b"act-1", b"act-2"))
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False


@pytest.mark.parametrize("exc", [HelloError("cancelled"), TimeoutError(), RuntimeError("x")])
def test_prove_refuses_when_signing_fails(marker, signer, exc):
    signer(raises=exc)
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False


def test_prove_refuses_a_malformed_action_without_signing(marker, signer):
    assert hello_mode.prove(action_id="bad\nid", action_hash=_HASH)[0] is False
    assert signer.current().signed == []


def test_prove_refuses_without_a_single_pinned_key(tmp_path, marker, signer, monkeypatch):
    machine = tmp_path / "machine.json"
    _marker_with(machine, OTHER)
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [machine])
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False
    assert signer.current().signed == []


def test_prove_refuses_with_a_corrupt_marker(marker, signer):
    marker.write_text("{", encoding="utf-8")
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False


def test_prove_refuses_a_backend_that_cannot_be_built(marker, monkeypatch):
    def _boom():
        raise ImportError("no PowerShell")

    monkeypatch.setattr(hello_mode, "backend", _boom)
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False


# --- provider: show the action, then sign it -------------------------------------------------


class Prompter:
    def __init__(self, answer=True):
        self.answer, self.asked = answer, []

    def confirm(self, message):
        self.asked.append("confirm")
        return self.answer

    def read_code(self, message):  # pragma: no cover - must never be asked in the mode
        self.asked.append("code")
        return "000000"


@pytest.mark.parametrize("tier", [AuthTier.two_factor, AuthTier.role_elevation])
def test_provider_approval_carries_a_proof_bound_to_the_action(marker, signer, tier):
    action, prompter = _action(), Prompter()
    result = LocalAuthProvider().authenticate(_decision(), action, tier, prompter=prompter)
    assert result.approved is True
    assert prompter.asked == ["confirm"]
    assert result.proof.action_id == action.id
    assert result.proof.action_hash == hello_proof.action_hash(action)
    assert hello_proof.check_stored(result.proof, KEY.public_key)


def test_provider_a_no_at_the_confirm_signs_nothing(marker, signer):
    result = LocalAuthProvider().authenticate(
        _decision(), _action(), AuthTier.two_factor, prompter=Prompter(answer=False)
    )
    assert result.approved is False and result.proof is None
    assert signer.current().signed == []


def test_provider_wrong_key_denies_with_no_proof(marker, signer):
    signer(key=OTHER)
    result = LocalAuthProvider().authenticate(
        _decision(), _action(), AuthTier.two_factor, prompter=Prompter()
    )
    assert result.approved is False and result.proof is None
    assert result.method == hello_mode.HELLO_REQUIRED_METHOD


def test_run_tier_alone_cannot_approve_proof_tier_in_the_mode(marker, signer):
    approved, method = LocalAuthProvider._run_tier(AuthTier.two_factor, "m", Prompter(), "act-1")
    assert approved is False
    assert signer.current().signed == []


def test_mode_off_results_carry_no_proof(tmp_path, monkeypatch, signer):
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    result = LocalAuthProvider().authenticate(
        _decision(), _action(), AuthTier.local_auth, prompter=Prompter()
    )
    assert result.approved is True and result.proof is None
    assert signer.current().signed == []


# --- evidence on disk ---------------------------------------------------------------------


def test_the_challenge_stores_the_proof_and_it_checks_later(marker, signer, tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    # a cold first database open can take longer than the production 5 s bound on slow CI
    monkeypatch.setattr("doberman.auth.challenge._MEMORY_IO_TIMEOUT_S", 120.0)
    action = _action()
    root = str(tmp_path / "repo")
    result = run_auth_challenge(_decision(), action, prompter=Prompter(), repo_root=root)
    assert result.approved is True
    stored = asyncio.run(hello_proofs.for_action(action.id, repo_root=root))
    assert stored == [result.proof]
    assert hello_proof.check_stored(stored[0], KEY.public_key)


def test_a_failed_proof_stores_nothing(marker, signer, tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    signer(key=OTHER)
    action = _action()
    root = str(tmp_path / "repo")
    assert (
        run_auth_challenge(_decision(), action, prompter=Prompter(), repo_root=root).approved
        is False
    )
    assert asyncio.run(hello_proofs.for_action(action.id, repo_root=root)) == []


def test_a_stored_nonce_or_signature_cannot_be_stored_twice(tmp_path):
    import sqlite3

    root = str(tmp_path)
    proof = dataclasses.replace(_signed(), key_id=hello_proof.key_id(KEY.public_key))
    asyncio.run(hello_proofs.record(proof, repo_root=root))
    with pytest.raises(sqlite3.IntegrityError):
        asyncio.run(hello_proofs.record(proof, repo_root=root))


def test_the_proof_table_holds_no_action_content(tmp_path):
    async def _cols():
        async with open_db(str(tmp_path)) as conn:
            async with conn.execute("PRAGMA table_info(hello_proofs)") as cur:
                return [row[1] for row in await cur.fetchall()]

    cols = asyncio.run(_cols())
    assert cols == [
        "id",
        "action_id",
        "action_hash",
        "signed_at",
        "nonce",
        "key_id",
        "signature",
        "stored_at",
    ]


def test_a_storage_failure_never_changes_the_answer(marker, signer, tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)

    async def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(hello_proofs, "record", _boom)
    result = run_auth_challenge(
        _decision(), _action(), prompter=Prompter(), repo_root=str(tmp_path)
    )
    assert result.approved is True


# --- policy weaken gate and leave ----------------------------------------------------------


def test_weaken_gate_needs_a_verifying_signature(marker, signer):
    assert drift._run_weaken_gate({"a": 1}, {"a": 0}, "r", Prompter()) == (True, "windows_hello")
    signer(key=OTHER)
    assert drift._run_weaken_gate({"a": 1}, {"a": 0}, "r", Prompter())[0] is False


def test_a_version_18_database_gains_the_proof_table_and_keeps_its_rows(tmp_path):
    import aiosqlite

    from doberman.storage.db import SCHEMA_VERSION, db_path

    root = str(tmp_path)

    async def _setup_v18():
        async with open_db(root) as conn:
            await conn.execute(
                "INSERT INTO decisions (ts, action_id, final_verdict) VALUES ('t', 'a1', 'AUTH')"
            )
            await conn.commit()
        async with aiosqlite.connect(str(db_path(root))) as conn:
            await conn.execute("DROP TABLE hello_proofs")
            await conn.execute("UPDATE schema_version SET version = 18")
            await conn.commit()

    async def _after():
        async with open_db(root) as conn:
            async with conn.execute("SELECT version FROM schema_version") as cur:
                version = [r[0] for r in await cur.fetchall()]
            async with conn.execute("SELECT action_id FROM decisions") as cur:
                rows = [r[0] for r in await cur.fetchall()]
        return version, rows

    asyncio.run(_setup_v18())
    proof = dataclasses.replace(_signed(), key_id=hello_proof.key_id(KEY.public_key))
    asyncio.run(hello_proofs.record(proof, repo_root=root))
    assert asyncio.run(_after()) == ([SCHEMA_VERSION], ["a1"])
    assert asyncio.run(hello_proofs.for_action("act-1", repo_root=root)) == [proof]


# --- slice 4: binding-review notes from #833 ----------------------------------------------


@pytest.mark.parametrize(
    "action_id",
    [
        "0f8fad5bd9cb469fa16570867728950e",  # uuid4().hex: the hook and proxy action id
        "toolu_01A09q90qw90lq917835lq9",  # a Claude Code tool_use_id
        "call_abc123XYZ",  # an OpenAI-style call id
        "exec-1b4e28ba-2fa1-11d2-883f-0016d3cca427",  # a Codex tool_use_id
        "policy-weaken",
        "hello-leave",
        "hello-enroll",
        "turn-error",
    ],
)
def test_real_action_id_sources_can_be_signed(action_id):
    assert _signed(action_id=action_id).message().startswith(b"doberman-proof-v1\n")


@pytest.mark.parametrize("action_id", ["a=b", "a\nb", "a b", "a\rb", "a\x00b", "é"])
def test_an_action_id_with_framing_characters_cannot_be_signed(action_id):
    with pytest.raises(ValueError):
        hello_proof.Proof(action_id, _HASH, _NOW, "0f" * 16).message()


def test_an_auth_result_with_a_proof_serializes_to_json():
    from doberman.auth.challenge import AuthResult

    proof = dataclasses.replace(_signed(), key_id=hello_proof.key_id(KEY.public_key))
    assert any(b > 0x7F for b in proof.signature)  # not valid UTF-8 as raw bytes
    result = AuthResult(
        approved=True,
        tier=AuthTier.two_factor,
        method="windows_hello",
        at="2026-11-14T00:00:00+00:00",
        action_id="act-1",
        proof=proof,
    )
    text = result.model_dump_json()
    assert base64.urlsafe_b64encode(proof.signature).decode() in text
    assert AuthResult.model_validate_json(text).proof == proof


class _LookAlike:
    """A plugin provider's result that quacks like AuthResult but has no ``proof``."""

    def __init__(self, action_id):
        self.approved, self.action_id, self.method = True, action_id, "plugin"


def test_a_plugin_result_without_a_proof_attribute_is_returned_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    action = _action()

    class _Plugin:
        def authenticate(self, *a, **k):
            return _LookAlike(action.id)

    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: _Plugin())
    result = run_auth_challenge(_decision(), action, prompter=Prompter(), repo_root=str(tmp_path))
    assert isinstance(result, _LookAlike) and result.approved is True


def test_the_proof_is_stored_when_the_challenge_runs_on_an_event_loop(
    marker, signer, tmp_path, monkeypatch
):
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    # a cold first database open can take longer than the production 5 s bound on slow CI
    monkeypatch.setattr("doberman.auth.challenge._MEMORY_IO_TIMEOUT_S", 120.0)
    action = _action()
    root = str(tmp_path / "repo")

    async def _on_loop():
        return run_auth_challenge(_decision(), action, prompter=Prompter(), repo_root=root)

    result = asyncio.run(_on_loop())
    assert result.approved is True
    assert asyncio.run(hello_proofs.for_action(action.id, repo_root=root)) == [result.proof]


def test_a_proof_storage_failure_logs_what_was_lost(marker, signer, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)

    async def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(hello_proofs, "record", _boom)
    with caplog.at_level("WARNING", logger="doberman.auth.challenge"):
        run_auth_challenge(_decision(), _action(), prompter=Prompter(), repo_root=str(tmp_path))
    text = caplog.text
    assert "Hello proof" in text and "not stored" in text
    assert "approval-memory" not in text
