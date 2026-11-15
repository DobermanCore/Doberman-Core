"""The child process that makes one Windows Hello signature (ADR 0119, slice 3).

Run as ``python -P -m doberman.auth.hello_signer`` by
:class:`~doberman.auth.methods.windows_hello.SignerProcessBackend`. Reads
``{"data": <base64>, "timeout_s": <seconds>}`` on stdin, asks for a Hello gesture to sign
``data`` with the ``doberman-proof`` key, and writes ``{"signature": <base64>}`` on stdout.
Any failure exits 1 with nothing on stdout.

Its parent does not trust it: the parent made the message and checks the signature against
the key pinned in the machine marker. Running here keeps a native failure in the prompt out
of the hook process.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import IO

from doberman.auth.methods.windows_hello import WinRTHelloBackend


def main(stdin: IO[bytes] | None = None, stdout: IO[str] | None = None) -> int:
    try:
        request = json.loads((stdin or sys.stdin.buffer).read())
        data = base64.b64decode(request["data"], validate=True)
        timeout_s = float(request["timeout_s"])
        signature = WinRTHelloBackend().sign(data, timeout_s=timeout_s)
    except Exception as exc:  # noqa: BLE001 - every failure is a refusal the parent sees
        print(f"hello signer: {type(exc).__name__}", file=sys.stderr)
        return 1
    (stdout or sys.stdout).write(json.dumps({"signature": base64.b64encode(signature).decode()}))
    return 0


if __name__ == "__main__":  # pragma: no cover - the child process entry point
    raise SystemExit(main())
