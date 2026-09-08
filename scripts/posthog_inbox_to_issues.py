"""Mirror PostHog Self-driving inbox reports into GitHub issues labelled ``posthog``.

PostHog's Self-driving inbox can open pull requests but cannot file GitHub issues, and
this project keeps its agent pull requests switched off: maintainers do the fixing.
This script closes the gap. Every report that is visible in the inbox and not yet
mirrored becomes one GitHub issue carrying the ``posthog`` label, a priority prefix,
the scout that found it, and a link back to the report. A hidden marker in the issue
body keys the deduplication, so re-running is idempotent.

Runs from ``.github/workflows/posthog-inbox.yml`` every six hours. Environment:

- ``POSTHOG_API_KEY``: a personal API key with the ``task:read`` scope (reports live
  under PostHog's task scope). Missing key = print a notice and exit 0, so a fork or an
  unconfigured checkout never turns the schedule red.
- ``GITHUB_TOKEN`` and ``GITHUB_REPOSITORY``: provided by GitHub Actions.
- ``POSTHOG_PROJECT_ID`` (default 579731) and ``POSTHOG_HOST`` (default us.posthog.com).

Stdlib only, HTTPS only, at most ``MAX_NEW_ISSUES_PER_RUN`` new issues per run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

LABEL = "posthog"
LABEL_COLOR = "F54E00"
LABEL_DESCRIPTION = "Filed automatically from the PostHog Self-driving inbox"
MARKER = re.compile(r"<!-- posthog-report: ([0-9a-fA-F-]{36}) -->")
# Inbox states a human can act on. ``potential`` reports are not surfaced yet, and the
# resolved / failed / suppressed / PostHog-internal states are not work for maintainers.
MIRRORED_STATUSES = frozenset({"candidate", "pending_input", "in_progress", "ready"})
DEFAULT_HOST = "https://us.posthog.com"
DEFAULT_PROJECT_ID = "579731"
GITHUB_API = "https://api.github.com"
MAX_NEW_ISSUES_PER_RUN = 20
TITLE_LIMIT = 200
PAGE_SIZE = 100

# (method, url, headers, body) -> (status, headers, body). Injected so tests never touch
# the network and so the transport is decided once, at construction.
Fetch = Callable[[str, str, dict[str, str], bytes | None], tuple[int, dict[str, str], bytes]]


def urllib_fetch(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, dict[str, str], bytes]:
    """The one real transport: HTTPS only, 30 s timeout, HTTP errors returned not raised."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS url: {url}")
    request = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - scheme checked
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


@dataclass(frozen=True)
class PostHog:
    host: str
    project_id: str
    api_key: str
    fetch: Fetch

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def reports(self) -> Iterator[dict[str, Any]]:
        """Every report the inbox API lists, following pagination."""
        url: str | None = (
            f"{self.host}/api/projects/{self.project_id}/signals/reports/?limit={PAGE_SIZE}"
        )
        while url:
            status, _headers, raw = self.fetch("GET", url, self._headers(), None)
            if status != 200:
                raise RuntimeError(f"PostHog reports request failed: {status} {raw[:200]!r}")
            page = json.loads(raw)
            yield from page.get("results", [])
            url = page.get("next")

    def report_url(self, report_id: str) -> str:
        return f"{self.host}/project/{self.project_id}/inbox/reports/{report_id}"


@dataclass(frozen=True)
class GitHub:
    repository: str
    token: str
    fetch: Fetch

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "doberman-posthog-inbox",
            "Content-Type": "application/json",
        }

    def mirrored_report_ids(self) -> set[str]:
        """Report ids already carried by an open or closed ``posthog`` issue."""
        ids: set[str] = set()
        page = 1
        while True:
            url = (
                f"{GITHUB_API}/repos/{self.repository}/issues"
                f"?labels={LABEL}&state=all&per_page={PAGE_SIZE}&page={page}"
            )
            status, _headers, raw = self.fetch("GET", url, self._headers(), None)
            if status != 200:
                raise RuntimeError(f"GitHub issues request failed: {status} {raw[:200]!r}")
            issues = json.loads(raw)
            for issue in issues:
                match = MARKER.search(issue.get("body") or "")
                if match:
                    ids.add(match.group(1).lower())
            if len(issues) < PAGE_SIZE:
                return ids
            page += 1

    def ensure_label(self) -> None:
        url = f"{GITHUB_API}/repos/{self.repository}/labels/{LABEL}"
        status, _headers, raw = self.fetch("GET", url, self._headers(), None)
        if status == 200:
            return
        if status != 404:
            raise RuntimeError(f"GitHub label lookup failed: {status} {raw[:200]!r}")
        payload = {"name": LABEL, "color": LABEL_COLOR, "description": LABEL_DESCRIPTION}
        status, _headers, raw = self.fetch(
            "POST", f"{GITHUB_API}/repos/{self.repository}/labels", self._headers(), _dump(payload)
        )
        # 422 = the label appeared between the lookup and the create; that is fine.
        if status not in (201, 422):
            raise RuntimeError(f"GitHub label create failed: {status} {raw[:200]!r}")

    def create_issue(self, title: str, body: str) -> str:
        payload = {"title": title, "body": body, "labels": [LABEL]}
        status, _headers, raw = self.fetch(
            "POST", f"{GITHUB_API}/repos/{self.repository}/issues", self._headers(), _dump(payload)
        )
        if status != 201:
            raise RuntimeError(f"GitHub issue create failed: {status} {raw[:200]!r}")
        return str(json.loads(raw)["html_url"])


def _dump(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


def is_mirrorable(report: dict[str, Any]) -> bool:
    return (
        report.get("status") in MIRRORED_STATUSES
        and not report.get("already_addressed")
        and not report.get("dismissal_reason")
    )


def issue_title(report: dict[str, Any]) -> str:
    title = " ".join(str(report.get("title") or "Untitled PostHog report").split())
    priority = report.get("priority")
    prefix = f"[{priority}] " if priority else ""
    return (prefix + title)[:TITLE_LIMIT]


def issue_body(report: dict[str, Any], report_url: str) -> str:
    summary = str(report.get("summary") or "").strip() or "_PostHog has not written a summary yet._"
    facts = [
        f"- Scout: `{report['scout_name']}`" if report.get("scout_name") else None,
        f"- Actionability: `{report['actionability']}`" if report.get("actionability") else None,
        f"- Inbox status: `{report.get('status', 'unknown')}`",
        f"- Signals behind it: {report.get('signal_count', 0)}",
    ]
    return "\n".join(
        [
            summary,
            "",
            *[fact for fact in facts if fact],
            "",
            f"[Open the report in PostHog]({report_url})",
            "",
            "_Filed automatically from the PostHog Self-driving inbox. It mirrors the finding;"
            " the fix is a maintainer's call._",
            f"<!-- posthog-report: {str(report['id']).lower()} -->",
        ]
    )


def sync(
    posthog: PostHog,
    github: GitHub,
    *,
    dry_run: bool = False,
    limit: int = MAX_NEW_ISSUES_PER_RUN,
    out: Callable[[str], None] = print,
) -> int:
    """File one issue per unmirrored, actionable report. Returns how many were filed."""
    mirrored = github.mirrored_report_ids()
    created = 0
    for report in posthog.reports():
        report_id = str(report.get("id", "")).lower()
        if not report_id or not is_mirrorable(report) or report_id in mirrored:
            continue
        if created >= limit:
            out(f"reached {limit} new issues; the rest wait for the next run")
            break
        title = issue_title(report)
        if dry_run:
            out(f"would file: {title}")
        else:
            if created == 0:
                github.ensure_label()
            url = github.create_issue(title, issue_body(report, posthog.report_url(report_id)))
            out(f"filed {url} for report {report_id}")
        created += 1
    out(f"{created} new issue(s); {len(mirrored)} report(s) were already mirrored")
    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true", help="print instead of filing")
    args = parser.parse_args(argv)

    api_key = os.environ.get("POSTHOG_API_KEY", "")
    if not api_key:
        print("POSTHOG_API_KEY is not set; nothing to mirror (this is expected on forks)")
        return 0
    token = os.environ.get("GITHUB_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repository:
        print("GITHUB_TOKEN and GITHUB_REPOSITORY are required", file=sys.stderr)
        return 2

    posthog = PostHog(
        host=os.environ.get("POSTHOG_HOST", DEFAULT_HOST).rstrip("/"),
        project_id=os.environ.get("POSTHOG_PROJECT_ID", DEFAULT_PROJECT_ID),
        api_key=api_key,
        fetch=urllib_fetch,
    )
    github = GitHub(repository=repository, token=token, fetch=urllib_fetch)
    sync(posthog, github, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
