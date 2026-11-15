"""Signed Hello proofs kept as audit evidence (ADR 0119, slice 3).

One row per proof-tier approval in Hello-required mode, joined to the decision log by
``action_id``. A row holds only what was signed (the action id, the keyed action hash, the
timestamp and nonce), the pinned key's id and the signature, so anyone with the pinned
public key can re-check it later with :func:`doberman.auth.hello_proof.check_stored`.
No action content, prompt or secret is stored. ``nonce`` and ``signature`` are UNIQUE.
"""

import base64
from datetime import datetime, timezone

from doberman.auth.hello_proof import Proof
from doberman.storage.db import open_db

_INSERT = (
    "INSERT INTO hello_proofs "
    "(action_id, action_hash, signed_at, nonce, key_id, signature, stored_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)
_SELECT = (
    "SELECT action_id, action_hash, signed_at, nonce, signature, key_id FROM hello_proofs "
    "WHERE action_id = ? ORDER BY id"
)


async def record(proof: Proof, *, repo_root: str = ".") -> None:
    """Store one proof. Raises ``sqlite3.IntegrityError`` on a repeated nonce or signature."""
    async with open_db(repo_root) as conn:
        await conn.execute(
            _INSERT,
            (
                proof.action_id,
                proof.action_hash,
                proof.signed_at,
                proof.nonce,
                proof.key_id,
                base64.b64encode(proof.signature).decode("ascii"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        await conn.commit()


async def for_action(action_id: str, *, repo_root: str = ".") -> list[Proof]:
    """Every stored proof for ``action_id``, oldest first."""
    async with open_db(repo_root) as conn:
        async with conn.execute(_SELECT, (action_id,)) as cur:
            rows = await cur.fetchall()
    return [
        Proof(aid, ahash, int(signed_at), nonce, base64.b64decode(sig), key)
        for aid, ahash, signed_at, nonce, sig, key in rows
    ]
