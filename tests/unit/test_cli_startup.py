"""Cold-start guard: the CLI must not pull the heavy numeric stack on import.

`doberman --help` / `log` / `status` / `scan` and the rest of the CLI only need
Typer + the policy/storage/discovery modules. The subjective layer's numeric
stack (``river`` → ``numpy`` / ``scipy``) is needed ONLY by ``doberman serve``.
Importing it on every CLI invocation added ~2.6s of cold-start latency, so the
serve entrypoint must be imported lazily (inside the ``serve`` command body).

The assertion runs in a CLEAN subprocess: other tests in this process may have
already imported the heavy modules, so an in-process check would be unreliable.
"""

import subprocess
import sys


def test_cli_import_does_not_pull_the_heavy_numeric_stack():
    code = (
        "import doberman.cli.main, sys; "
        "heavy = sorted(m for m in sys.modules if m.split('.')[0] in "
        "('river', 'scipy', 'numpy')); "
        "print(','.join(heavy)); "
        "sys.exit(1 if heavy else 0)"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"`import doberman.cli.main` pulled the heavy numeric stack: "
        f"{result.stdout.strip()!r} (stderr: {result.stderr.strip()!r})"
    )
