"""The committed docs/PARITY.md must stay in sync with the guarantee markers (W3).

Runs the generator in ``--check`` mode: a claimed ✅ whose test was renamed or
deleted, a marker naming an unknown guarantee/host, an N/A cell that gained a
claiming test, or a stale committed doc all turn this red — so the matrix can
never drift from the tests it claims to be backed by.
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_parity_doc_is_current():
    proc = subprocess.run(
        [sys.executable, "-m", "tools.parity.generate_parity", "--check"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "docs/PARITY.md is stale or a guarantee marker is invalid — run "
        f"`python -m tools.parity.generate_parity`:\n{proc.stdout}{proc.stderr}"
    )
