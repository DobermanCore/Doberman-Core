"""Pytest plugin: ``--parity-dump PATH`` writes every ``@pytest.mark.guarantee``
cell claim as JSON during collection.

Loaded explicitly with ``-p tools.parity.pytest_parity``; never active in a normal
test run (the option defaults to off).
"""

import json
from pathlib import Path


def pytest_addoption(parser):
    parser.addoption("--parity-dump", action="store", default=None)


def pytest_collection_finish(session):
    path = session.config.getoption("--parity-dump")
    if not path:
        return
    cells = []
    for item in session.items:
        for mark in item.iter_markers(name="guarantee"):
            cells.append(
                {
                    "guarantee": mark.args[0] if mark.args else None,
                    "host": mark.kwargs.get("host"),
                    "test": item.nodeid,
                }
            )
    Path(path).write_text(json.dumps(cells, indent=2), encoding="utf-8")
