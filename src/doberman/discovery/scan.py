"""Capability enumeration, risk rating, and risk-map rendering (Feature 5).

``enumerate_capabilities`` infers what an agent can do from (a) the downstream
**tool list** and (b) a **read-only** scan of the repository's sensitive
surface. ``rate_capabilities`` assigns a :class:`~doberman.models.Risk` to each,
and ``render_risk_map`` turns them into a readable report.

SECURITY:

* The scan is strictly **read-only** and never opens a secret file's *contents*
  — sensitive assets are detected by **name/existence** only.
* The scan never writes anywhere (let alone outside ``.doberman/``).
* The risk map contains capability names, categories, risk levels, and
  path-class evidence — **never** file contents or secret material.
* The scan is depth- and count-bounded so a huge or hostile repo cannot make it
  run unbounded, and per-entry permission errors are skipped (and noted), never
  raised into the caller.
"""

import fnmatch
import os
from dataclasses import dataclass, replace

from doberman.models import Risk

#: Bounds so a pathological repo cannot make the scan run unbounded.
_MAX_DEPTH = 8
_MAX_ENTRIES = 20_000

#: Directories never worth scanning (huge, and not the agent's sensitive surface).
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".doberman", "dist", "build"}
)


@dataclass(frozen=True)
class Capability:
    """One discovered capability (immutable).

    ``evidence`` holds path classes / tool names that triggered detection —
    never file contents. ``risk`` is ``None`` until :func:`rate_capabilities`.
    """

    name: str
    category: str
    present: bool
    evidence: tuple[str, ...] = ()
    risk: Risk | None = None


#: Tool-derived capabilities: capability name → (substring patterns, description).
#: A capability is present if any tool name (lower-cased) contains a pattern.
_TOOL_CAPABILITIES: dict[str, tuple[tuple[str, ...], str]] = {
    "shell": (
        ("shell", "exec", "bash", "command", "subprocess", "terminal"),
        "Execute shell commands",
    ),
    "filesystem_write": (
        ("write", "edit", "create", "save", "mkdir", "put_file"),
        "Write or modify files",
    ),
    "filesystem_delete": (("delete", "unlink", "rmdir", "remove_file", "rm_"), "Delete files"),
    "filesystem_read": (("read", "cat_", "open_file", "get_file", "view_file"), "Read files"),
    "network": (
        ("net", "http", "fetch", "url", "request", "curl", "download", "webhook"),
        "Make network requests",
    ),
    "git": (("git",), "Run git operations"),
    "git_push": (("push", "force_push"), "Push to remotes (including force-push)"),
    "package_install": (
        ("install", "pip_", "npm", "yarn", "apt", "brew", "cargo"),
        "Install packages",
    ),
    "env_access": (
        ("getenv", "environ", "env_var", "secret"),
        "Access environment variables / secrets",
    ),
}

#: Sensitive-surface capabilities: name → (glob patterns, description). A glob
#: ending in "/" matches a directory name; others match file names.
_SENSITIVE_SURFACE: dict[str, tuple[tuple[str, ...], str]] = {
    "dotenv_visible": ((".env", ".env.*"), "Environment/secret files present"),
    "secret_files": (("*.pem", "*.key", "id_rsa*", "id_ed25519*"), "Private key material present"),
    "secrets_dir": (("secrets/",), "secrets/ directory present"),
    "infra": (("infra/", "*.tf", "*.tfstate"), "Infrastructure-as-code present"),
    "ci_workflows": ((".github/", "*.yml", "*.yaml"), "CI/CD workflow surface present"),
    "migrations": (("migrations/",), "Database migrations present"),
}


def _tool_capabilities(tools: list[str]) -> list[Capability]:
    lowered = [(t, t.lower()) for t in tools if isinstance(t, str)]
    caps: list[Capability] = []
    for name, (patterns, description) in _TOOL_CAPABILITIES.items():
        evidence = tuple(sorted({orig for orig, low in lowered if any(p in low for p in patterns)}))
        caps.append(
            Capability(
                name=name,
                category="tool",
                present=bool(evidence),
                evidence=evidence if evidence else (description,),
            )
        )
    return caps


def _walk_names(repo_root: str) -> tuple[list[tuple[str, bool]], bool]:
    """Yield (relative-posix-path, is_dir) for entries under ``repo_root``.

    Bounded by depth and entry count; skips heavy/irrelevant dirs and any entry
    that raises a permission error. Returns the entries plus a ``truncated``
    flag (True if a bound or permission error curtailed the scan).
    """
    root = os.path.abspath(repo_root)
    entries: list[tuple[str, bool]] = []
    truncated = False
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        if depth >= _MAX_DEPTH:
            dirnames[:] = []
            truncated = True
            continue
        # Prune heavy dirs in place so os.walk does not descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for d in dirnames:
            rel = os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/")
            entries.append((rel + "/", True))
        for f in filenames:
            rel = os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")
            entries.append((rel, False))
            count += 1
            if count >= _MAX_ENTRIES:
                return entries, True
    return entries, truncated


def _matches(name_relposix: str, is_dir: bool, pattern: str) -> bool:
    base = name_relposix.rsplit("/", 1)[-1] if not name_relposix.endswith("/") else name_relposix
    if pattern.endswith("/"):
        # Directory pattern: match the directory's base name anywhere in the tree.
        if not is_dir:
            return False
        dir_base = name_relposix.rstrip("/").rsplit("/", 1)[-1] + "/"
        return fnmatch.fnmatch(dir_base, pattern) or fnmatch.fnmatch(name_relposix, "*" + pattern)
    if is_dir:
        return False
    return fnmatch.fnmatch(base, pattern)


def _surface_capabilities(repo_root: str) -> tuple[list[Capability], bool]:
    entries, truncated = _walk_names(repo_root)
    caps: list[Capability] = []
    for name, (patterns, description) in _SENSITIVE_SURFACE.items():
        evidence: list[str] = []
        for rel, is_dir in entries:
            if any(_matches(rel, is_dir, p) for p in patterns):
                evidence.append(rel)
        # Cap evidence list so the map stays readable; we record names, never contents.
        unique = sorted(set(evidence))[:10]
        caps.append(
            Capability(
                name=name,
                category="sensitive_surface",
                present=bool(unique),
                evidence=tuple(unique) if unique else (description,),
            )
        )
    return caps, truncated


def enumerate_capabilities(tools: list[str], repo_root: str = ".") -> list[Capability]:
    """Enumerate agent capabilities from the tool list and a read-only repo scan.

    Read-only; never opens secret-file contents (detection is by name/existence)
    and never writes anywhere. Returns one :class:`Capability` per known
    capability (present or not), unrated (see :func:`rate_capabilities`).
    """
    caps = _tool_capabilities(tools or [])
    surface, _truncated = _surface_capabilities(repo_root)
    return caps + surface


#: Risk rating per capability (raise-only spirit: when unsure, rate higher).
_RISK_BY_CAPABILITY: dict[str, Risk] = {
    "dotenv_visible": Risk.critical,
    "secret_files": Risk.critical,
    "secrets_dir": Risk.critical,
    "shell": Risk.high,
    "filesystem_write": Risk.high,
    "filesystem_delete": Risk.high,
    "network": Risk.high,
    "git_push": Risk.high,
    "package_install": Risk.high,
    "env_access": Risk.high,
    "infra": Risk.high,
    "git": Risk.medium,
    "ci_workflows": Risk.medium,
    "migrations": Risk.medium,
    "filesystem_read": Risk.low,
}


def rate_capabilities(capabilities: list[Capability]) -> list[Capability]:
    """Return copies of ``capabilities`` with a :class:`Risk` assigned to each.

    On a conflicting/unknown signal we default to ``medium`` (never silently
    low) — discovery should over-, not under-state blast radius.
    """
    return [
        replace(cap, risk=_RISK_BY_CAPABILITY.get(cap.name, Risk.medium)) for cap in capabilities
    ]


_RISK_RANK = {Risk.critical: 3, Risk.high: 2, Risk.medium: 1, Risk.low: 0}


def render_risk_map(capabilities: list[Capability]) -> str:
    """Render a readable risk map. Present capabilities first, then by risk desc.

    Contains capability names, risk, and path-class/tool evidence only — never
    file contents.
    """
    rated = [c if c.risk is not None else replace(c, risk=Risk.medium) for c in capabilities]
    rated.sort(key=lambda c: (not c.present, -_RISK_RANK[c.risk], c.name))

    lines = ["Doberman capability risk map", "=" * 32]
    for cap in rated:
        marker = cap.risk.value.upper() if cap.present else "—"
        status = "present" if cap.present else "absent"
        evidence = ", ".join(cap.evidence[:3]) if cap.present else ""
        line = f"[{marker:^8}] {cap.name:<20} ({status})"
        if evidence:
            line += f"  ← {evidence}"
        lines.append(line)
    lines.append("")
    lines.append(
        "Heuristic, read-only scan. Sensitive files are detected by name only (never read)."
    )
    return "\n".join(lines)
