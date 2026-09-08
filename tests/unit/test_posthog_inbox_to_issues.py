"""The PostHog inbox mirror files one labelled issue per new report and never twice."""

from __future__ import annotations

import json
from typing import Any

import pytest

from scripts.posthog_inbox_to_issues import (
    LABEL,
    MARKER,
    PAGE_SIZE,
    GitHub,
    PostHog,
    is_mirrorable,
    issue_body,
    issue_title,
    main,
    sync,
)

REPORT = {
    "id": "01A0830C-98F1-7CB3-998A-94ECB2EFDB79",
    "title": "  Authorization outcomes are\n silent for active CLI traffic ",
    "summary": "AUTH verdicts arrive with no approved or denied outcome.",
    "status": "pending_input",
    "priority": "P2",
    "actionability": "requires_human_input",
    "scout_name": "signals-scout-authorization-decision-health",
    "signal_count": 4,
}


class FakeTransport:
    """Scripted (method, path) -> (status, json) responses that record every call."""

    def __init__(self, routes: dict[tuple[str, str], tuple[int, Any]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, dict[str, str], bytes]:
        path = url.split("//", 1)[1].split("/", 1)[1]
        self.calls.append((method, path, json.loads(body) if body else None))
        for (route_method, route_path), (status, payload) in self.routes.items():
            if route_method == method and path.startswith(route_path):
                return status, {}, json.dumps(payload).encode()
        raise AssertionError(f"unexpected request {method} {path}")


def _clients(
    routes: dict[tuple[str, str], tuple[int, Any]],
) -> tuple[PostHog, GitHub, FakeTransport]:
    transport = FakeTransport(routes)
    posthog = PostHog(host="https://us.posthog.com", project_id="1", api_key="k", fetch=transport)
    github = GitHub(repository="org/repo", token="t", fetch=transport)  # noqa: S106
    return posthog, github, transport


def _routes(reports: list[dict[str, Any]], issues: list[dict[str, Any]]) -> dict:
    return {
        ("GET", "api/projects/1/signals/reports/"): (200, {"results": reports, "next": None}),
        ("GET", "repos/org/repo/issues?labels="): (200, issues),
        ("GET", "repos/org/repo/labels/posthog"): (404, {}),
        ("POST", "repos/org/repo/labels"): (201, {}),
        ("POST", "repos/org/repo/issues"): (
            201,
            {"html_url": "https://github.com/org/repo/issues/9"},
        ),
    }


def test_new_report_becomes_one_labelled_issue_with_marker_and_priority() -> None:
    posthog, github, transport = _clients(_routes([REPORT], []))
    out: list[str] = []

    assert sync(posthog, github, out=out.append) == 1

    creates = [call for call in transport.calls if call[:2] == ("POST", "repos/org/repo/issues")]
    assert len(creates) == 1
    payload = creates[0][2]
    assert payload["labels"] == [LABEL]
    assert payload["title"] == "[P2] Authorization outcomes are silent for active CLI traffic"
    assert MARKER.search(payload["body"]).group(1) == REPORT["id"].lower()
    assert "inbox/reports/01a0830c-98f1-7cb3-998a-94ecb2efdb79" in payload["body"]
    assert "signals-scout-authorization-decision-health" in payload["body"]
    assert ("POST", "repos/org/repo/labels") in [call[:2] for call in transport.calls]
    assert out[0].startswith("filed https://github.com/org/repo/issues/9")


def test_already_mirrored_reports_are_skipped_case_insensitively() -> None:
    existing = [{"body": f"old text\n<!-- posthog-report: {REPORT['id'].lower()} -->"}]
    posthog, github, transport = _clients(_routes([REPORT], existing))

    assert sync(posthog, github) == 0
    assert all(call[0] == "GET" for call in transport.calls)


def test_dry_run_files_nothing_and_says_what_it_would_file() -> None:
    posthog, github, transport = _clients(_routes([REPORT], []))
    out: list[str] = []

    assert sync(posthog, github, dry_run=True, out=out.append) == 1
    assert all(call[0] == "GET" for call in transport.calls)
    assert out[0] == "would file: [P2] Authorization outcomes are silent for active CLI traffic"


def test_per_run_cap_leaves_the_rest_for_the_next_run() -> None:
    reports = [dict(REPORT, id=f"01a0830c-98f1-7cb3-998a-94ecb2efdb{n:02d}") for n in range(3)]
    posthog, github, transport = _clients(_routes(reports, []))

    assert sync(posthog, github, limit=2) == 2
    assert sum(call[:2] == ("POST", "repos/org/repo/issues") for call in transport.calls) == 2


def test_mirrored_ids_follow_github_pagination() -> None:
    first_page = [
        {"body": f"<!-- posthog-report: {n:08d}-0000-0000-0000-000000000000 -->"}
        for n in range(PAGE_SIZE)
    ]
    routes = {
        ("GET", f"repos/org/repo/issues?labels=posthog&state=all&per_page={PAGE_SIZE}&page=1"): (
            200,
            first_page,
        ),
        ("GET", f"repos/org/repo/issues?labels=posthog&state=all&per_page={PAGE_SIZE}&page=2"): (
            200,
            [
                {"body": "<!-- posthog-report: ffffffff-0000-0000-0000-000000000000 -->"},
                {"body": None},
            ],
        ),
    }
    _posthog, github, _transport = _clients(routes)

    ids = github.mirrored_report_ids()

    assert len(ids) == PAGE_SIZE + 1
    assert "ffffffff-0000-0000-0000-000000000000" in ids


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, True),
        ({"status": "candidate"}, True),
        ({"status": "potential"}, False),
        ({"status": "resolved"}, False),
        ({"status": "posthog_health_check"}, False),
        ({"already_addressed": True}, False),
        ({"dismissal_reason": "not_a_bug"}, False),
    ],
)
def test_only_actionable_undismissed_reports_are_mirrored(
    changes: dict[str, Any], expected: bool
) -> None:
    assert is_mirrorable(dict(REPORT, **changes)) is expected


def test_title_and_body_shapes() -> None:
    assert issue_title({"title": "x" * 300, "priority": None}) == "x" * 200
    assert issue_title({}) == "Untitled PostHog report"
    body = issue_body({"id": "abc", "status": "ready"}, "https://x/report")
    assert body.startswith("_PostHog has not written a summary yet._")
    assert body.endswith("<!-- posthog-report: abc -->")


def test_missing_key_is_a_quiet_no_op(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("POSTHOG_API_KEY", raising=False)

    assert main([]) == 0
    assert "POSTHOG_API_KEY is not set" in capsys.readouterr().out


def test_missing_github_context_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTHOG_API_KEY", "k")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)

    assert main([]) == 2
