"""docs/schemas/policy-snapshot.v1.json must equal the model's generated schema."""

import json
from pathlib import Path

from doberman.storage.policy_catalogue import PolicySnapshotV1

SCHEMA_FILE = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "policy-snapshot.v1.json"


def test_published_schema_matches_the_model():
    expected = json.dumps(PolicySnapshotV1.model_json_schema(), indent=2, sort_keys=True) + "\n"
    assert SCHEMA_FILE.read_text(encoding="utf-8") == expected, (
        'regenerate with: python -c "import json; from doberman.storage.policy_catalogue import '
        'PolicySnapshotV1 as M; print(json.dumps(M.model_json_schema(), indent=2, sort_keys=True))"'
        " > docs/schemas/policy-snapshot.v1.json"
    )


def test_docs_index_and_cli_reference_mention_the_command():
    docs = Path(__file__).resolve().parents[2] / "docs"
    assert "POLICY_VERSIONS.md" in (docs / "README.md").read_text(encoding="utf-8")
    assert "policy-versions" in (docs / "CLI.md").read_text(encoding="utf-8")
