"""The ``doberman`` CLI entry point (Features 5-7).

Exposes ``doberman scan`` (risk map), ``review`` / ``mode`` / ``status``
(policy), and the Feature 7 auth surface: ``doberman 2fa setup`` (TOTP
enrollment) and ``doberman revoke`` (revoke a role elevation). ``status`` also
lists currently-active elevations.
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone

import typer

from doberman import __version__
from doberman.auth import totp
from doberman.config import (
    load_active_role,
    load_mode,
    load_policy,
    load_preferences,
    save_mode,
    save_policy,
    save_preferences,
)
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.policy.checklist import recommend_policy
from doberman.policy.drift import read_policy_changes
from doberman.policy.modes import SecurityMode
from doberman.policy.preferences import DIMENSIONS, preset_name
from doberman.storage.db import active_elevations, revoke_elevation
from doberman.storage.log import memory_summary, read_decisions


def _ensure_encode_safe_stdio() -> None:
    """Make CLI output safe on a console that cannot encode Unicode.

    Windows' default console is cp1252; printing a non-ASCII character (an arrow,
    box-drawing rule, or emoji) there raises ``UnicodeEncodeError`` and crashes
    onboarding (``doberman setup`` / ``install-hooks``). Reconfigure stdout/stderr
    to UTF-8 with error-replacement so output can never crash on the console
    encoding -- a no-op where ``reconfigure`` is unavailable. Runs at import,
    before any command emits a character.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # detached / unsupported stream
            pass


_ensure_encode_safe_stdio()

app = typer.Typer(
    help="Doberman - adaptive authorization layer for coding agents.",
    no_args_is_help=True,
    add_completion=False,
)

twofa_app = typer.Typer(help="Two-factor (TOTP) enrollment.", no_args_is_help=True)
app.add_typer(twofa_app, name="2fa")

hook_app = typer.Typer(
    help="Host-harness integration hooks (e.g. Claude Code PreToolUse/PostToolUse).",
    no_args_is_help=True,
)
app.add_typer(hook_app, name="hook")


def _configure_stderr_logging(level: int = logging.INFO) -> None:
    """Send Doberman logs to STDERR only.

    In ``serve`` mode this process's stdout IS the agent's MCP channel, so any log written
    there would corrupt the protocol. Pin every ``doberman.*`` logger to stderr and stop
    propagation, and - defense in depth - strip any stdout handler from the root logger so a
    library (mcp/asyncio) or host-configured logger cannot leak a record onto stdout either.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("doberman: %(message)s"))
    doberman_logger = logging.getLogger("doberman")
    for existing in doberman_logger.handlers[:]:
        doberman_logger.removeHandler(existing)
    doberman_logger.addHandler(handler)
    doberman_logger.setLevel(level)
    doberman_logger.propagate = False

    root = logging.getLogger()
    for existing in root.handlers[:]:
        if (
            isinstance(existing, logging.StreamHandler)
            and getattr(existing, "stream", None) is sys.stdout
        ):
            root.removeHandler(existing)
    if not root.handlers:  # keep a stderr fallback so non-doberman logs aren't silently dropped
        root.addHandler(logging.StreamHandler(sys.stderr))


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    help="Run Doberman as an MCP proxy in front of a downstream MCP tool server.",
)
def serve(
    ctx: typer.Context,
    path: str = typer.Option(
        ".", "--path", "-p", help="Repo root whose .doberman/ policy governs decisions."
    ),
) -> None:
    """Run Doberman as an MCP proxy in front of a downstream MCP server.

    Everything after `--` is the downstream server command, for example:

        doberman serve -- npx -y @modelcontextprotocol/server-filesystem /path/to/repo

    Point your agent's MCP config at this instead of the real server. AUTH prompts appear on
    your terminal; with no terminal attached (headless) an AUTH action is denied (fail closed).
    """
    # Imported here, not at module scope, so non-serve CLI commands (`--help`,
    # `log`, `status`, `scan`, ...) don't pay the cost of loading the subjective
    # layer's heavy numeric stack (river/numpy/scipy) on every invocation. These
    # imports run synchronously, before asyncio.run, so nothing loads in-loop.
    from mcp import StdioServerParameters

    from doberman.proxy.serve import serve_stdio

    downstream_argv = list(ctx.args)
    if not downstream_argv:
        typer.echo("error: provide the downstream server command after `--`", err=True)
        raise typer.Exit(code=2)
    params = StdioServerParameters(command=downstream_argv[0], args=downstream_argv[1:])
    _configure_stderr_logging()
    try:
        asyncio.run(serve_stdio(params, repo_root=path))
    except Exception as exc:  # noqa: BLE001 - surface a clean stderr error, never a raw traceback
        typer.echo(f"error: doberman serve failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Repository root to scan."),
) -> None:
    """Show a read-only risk map of the agent's capabilities and sensitive surface.

    Sensitive files are detected by name only and never read; nothing is written.
    Tool-derived capabilities require a live proxy session and are omitted here.
    """
    capabilities = rate_capabilities(enumerate_capabilities(tools=[], repo_root=path))
    typer.echo(render_risk_map(capabilities))


@app.command()
def review(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Accept the recommended policy and save it."
    ),
) -> None:
    """Review (and with --yes, save) the recommended policy checklist.

    Core hard blocks are shown but are not disableable here (that requires the
    policy-change approval flow). Without --yes this is read-only.
    """
    role = load_active_role(path)
    capabilities = rate_capabilities(enumerate_capabilities(tools=[], repo_root=path))
    doc = load_policy(path) or recommend_policy(role, capabilities)

    typer.echo("Doberman policy checklist")
    typer.echo("=" * 32)
    for item in doc.items:
        box = "[x]" if item.enabled else "[ ]"
        tags = []
        if item.core:
            tags.append("core/non-disableable")
        if not item.applicable:
            tags.append("N/A - capability absent")
        suffix = f"  ({', '.join(tags)})" if tags else ""
        typer.echo(f"{box} {item.verdict.value:<5} {item.id}{suffix}")
    typer.echo(f"\nMode: {doc.mode}")

    if yes:
        save_policy(doc, path)
        typer.echo(f"\nSaved policy to {path}/.doberman/policies.yaml")
    else:
        typer.echo("\n(read-only; re-run with --yes to save)")


@app.command()
def mode(
    name: str = typer.Argument(None, help="Mode to set (light/balanced/strict/paranoid)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the security strength mode."""
    if name is None:
        typer.echo(load_mode(path))
        return
    try:
        saved = save_mode(name, path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"mode set to {saved}")


@app.command()
def prefs(
    dimension: str = typer.Argument(
        None, help=f"Preference dimension to set ({', '.join(DIMENSIONS)})."
    ),
    value: float = typer.Argument(None, help="New weight in [0, 1]."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the subjective preference vector (SL5).

    With no arguments, prints the active vector and which mode preset it
    matches (if any). Weights tune SUBJECTIVE step-up propensity only - the
    objective hard-block floor is unaffected by every weight.
    """
    if dimension is None:
        vector = load_preferences(path)
        preset = preset_name(vector)
        typer.echo("Doberman preference vector")
        typer.echo("=" * 32)
        for name in DIMENSIONS:
            typer.echo(f"{name:<23} {getattr(vector, name):.2f}")
        typer.echo(f"preset: {preset or '(custom mix)'}")
        return
    if value is None:
        typer.echo(
            "error: provide a value in [0, 1] (e.g. `doberman prefs confidentiality 0.8`)", err=True
        )
        raise typer.Exit(code=2)
    try:
        updated = load_preferences(path).with_weight(dimension, value)
    except (KeyError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    save_preferences(updated, path)
    typer.echo(f"{dimension} set to {value:.2f}")


def _hook_install_states(path: str) -> list[tuple[str, str, bool]]:
    """Best-effort: for every Claude Code settings.json candidate (project / global /
    local — the same scopes ``install-hooks`` writes to), report whether Doberman's
    hooks are installed there.

    Never raises: an unreadable or unparseable settings file is reported as "not
    installed" rather than crashing ``status`` (mirrors ``install-hooks``'s own
    ``load_settings`` error handling, but status must not error out over it).
    """
    from doberman.hosthooks.install import _is_doberman_group, load_settings, resolve_settings_path

    states: list[tuple[str, str, bool]] = []
    for scope in ("project", "global", "local"):
        settings_path = resolve_settings_path(scope, path)
        installed = False
        try:
            settings = load_settings(settings_path)
            hooks_section = settings.get("hooks") or {}
            installed = any(
                _is_doberman_group(group)
                for groups in hooks_section.values()
                if isinstance(groups, list)
                for group in groups
            )
        except Exception:  # noqa: BLE001,S110 — a bad settings file must not crash status
            pass
        states.append((scope, str(settings_path), installed))
    return states


@app.command()
def status(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show the active role, security mode, policy summary, hook install state,
    and the most recent decisions."""
    role = load_active_role(path)
    doc = load_policy(path)
    typer.echo("Doberman status")
    typer.echo("=" * 32)
    typer.echo(f"Version: {__version__}")
    typer.echo(f"Role:   {role.name if role else '(none - role enforcement off)'}")
    typer.echo(f"Mode:   {load_mode(path)}  (of: {', '.join(m.value for m in SecurityMode)})")
    vector = load_preferences(path)
    typer.echo(
        "Prefs:  "
        + "  ".join(f"{name}={getattr(vector, name):.2f}" for name in DIMENSIONS)
        + f"  (preset: {preset_name(vector) or 'custom'})"
    )
    if doc is None:
        typer.echo("Policy: (none saved - run `doberman review --yes`)")
    else:
        enabled = sum(1 for it in doc.items if it.enabled)
        typer.echo(f"Policy: {enabled}/{len(doc.items)} items enabled")

    enrolled = "yes" if totp.is_enrolled() else "no (run `doberman 2fa setup`)"
    typer.echo(f"2FA:    {enrolled}")

    grants = asyncio.run(active_elevations(path, datetime.now(timezone.utc)))
    if not grants:
        typer.echo("Elevations: (none active)")
    else:
        typer.echo(f"Elevations: {len(grants)} active")
        for grant in grants:
            kind = "single-use" if grant.single_use else "reusable"
            typer.echo(
                f"  {grant.id}  {grant.scope_glob}  "
                f"(expires {grant.expires_at.isoformat()}; {kind})"
            )

    typer.echo("Hooks:")
    for scope, settings_path, installed in _hook_install_states(path):
        state = "installed" if installed else "not installed"
        typer.echo(f"  {scope:<8} {settings_path}  [{state}]")

    typer.echo("Recent decisions:")
    rows = asyncio.run(read_decisions(path, limit=5))
    if not rows:
        typer.echo("  (no decisions recorded yet)")
    else:
        for row in rows:
            reasons = ", ".join(json.loads(row["reason_codes_json"] or "[]")) or "-"
            typer.echo(f"  {row['ts']}  {row['final_verdict']:<5}  {reasons}")


@hook_app.command("pre")
def hook_pre() -> None:
    """Claude Code PreToolUse hook - gate one tool call (allow / ask / deny).

    Reads the harness hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS - Doberman is raise-only and never
    suppresses the harness's own prompts). Runs only the fast deterministic
    objective floor (no numpy/scipy/river), so it adds minimal latency to every
    tool call, and fails closed (deny) on any malformed input or engine error.

    Wire it into Claude Code's settings (a later slice adds `doberman
    install-hooks` to do this for you).
    """
    # This process's stdout IS the harness's hook channel (it parses our JSON), so
    # pin every doberman.* log to stderr and strip any stdout handler first - a
    # stray log line on stdout would corrupt the decision the harness reads (and a
    # malformed hook response can fail open). Same guard the `serve` command uses.
    _configure_stderr_logging()
    # Imported here, not at module scope, so the other CLI commands don't load
    # the decision path on every `--help`/`status`/`log` invocation.
    from doberman.hosthooks.claude_code import run_pre_hook

    out = run_pre_hook(sys.stdin.read())
    if out is not None:
        # The harness parses stdout as JSON; write ONLY the decision there, with a
        # trailing newline so a line-delimited reader sees a complete record.
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("post")
def hook_post() -> None:
    """Claude Code PostToolUse hook - scan tool output for secrets; record history.

    Reads the harness hook payload as JSON on stdin.  If the tool output
    contains credential-like material, writes ``{"decision":"block","reason":"..."}``
    to stdout (exit 0) so Claude never uses the tainted result.  On a clean
    output (or a non-gated / internal tool) nothing is written to stdout.

    History is best-effort: the call is always recorded in the local decision
    log when the tool is a gated built-in or an MCP tool, but a history write
    failure never blocks or raises.

    Runs only the fast deterministic objective floor (no numpy/scipy/river),
    fails closed on any malformed input or engine error.

    Wire it into Claude Code's settings (a later slice adds `doberman
    install-hooks` to do this for you).
    """
    _configure_stderr_logging()
    from doberman.hosthooks.claude_code import run_post_hook

    out = run_post_hook(sys.stdin.read())
    if out is not None:
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@twofa_app.command("setup")
def twofa_setup(
    force: bool = typer.Option(
        False, "--force", help="Rotate an existing secret (invalidates the old one)."
    ),
) -> None:
    """Enroll TOTP two-factor and print the provisioning URI for your authenticator."""
    try:
        uri = totp.enroll(force=force)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("2FA enrolled. Add this to your authenticator app (or scan it as a QR):")
    typer.echo(uri)
    typer.echo("This secret is stored locally with owner-only permissions and is never committed.")


@app.command()
def revoke(
    elevation_id: str = typer.Argument(..., help="Id of the elevation to revoke."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Revoke an active role elevation by id (see `doberman status`)."""
    revoked = asyncio.run(revoke_elevation(path, elevation_id))
    if revoked:
        typer.echo(f"revoked elevation {elevation_id}")
    else:
        typer.echo(f"no elevation with id {elevation_id}", err=True)
        raise typer.Exit(code=1)


@app.command()
def log(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N decisions."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show the recent redacted decision log (newest first).

    Every row is already redacted - a path class, reason codes, the verdict, and
    the auth outcome. No raw target, argument, or secret is ever stored or shown.
    """
    rows = asyncio.run(read_decisions(path, limit=max(0, last)))
    if not rows:
        typer.echo("(no decisions recorded yet)")
        return
    typer.echo("Doberman decision log")
    typer.echo("=" * 32)
    for row in rows:
        target = row["target_path_class"] or "-"
        reasons = ", ".join(json.loads(row["reason_codes_json"] or "[]")) or "-"
        auth = f"; auth={row['auth_result']}" if row["auth_result"] else ""
        typer.echo(
            f"{row['ts']}  {row['final_verdict']:<5} {row['action_type']:<13} "
            f"{target}  [{reasons}]{auth}"
        )


@app.command()
def memory(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show a plain-language, redaction-safe profile of what Doberman has learned.

    Reads as classifications and habits - counts, verdict mix, most-touched path
    classes, and how many distinct secrets have been *seen* (a count only). It
    never shows a fingerprint value or any raw secret.
    """
    summary = asyncio.run(memory_summary(path))
    typer.echo("Doberman learned memory")
    typer.echo("=" * 32)
    typer.echo(f"Decisions recorded: {summary['decisions']}")
    verdicts = summary["verdicts"]
    if verdicts:
        mix = ", ".join(f"{v}={n}" for v, n in verdicts.items())
        typer.echo(f"Verdict mix:        {mix}")
    if summary["top_path_classes"]:
        typer.echo("Most-touched path classes:")
        for cls, count in summary["top_path_classes"]:
            typer.echo(f"  {cls}  x{count}")
    typer.echo(f"Distinct secrets seen (count only, never stored): {summary['secrets_seen']}")


@app.command("policy-history")
def policy_history(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N changes."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show the append-only policy-change ledger (newest first).

    Records every classified change - strengthen / weaken / neutral - **including
    denied weakening attempts** (the poisoning signal). Each row shows the rule,
    the before->after states, the classification, and how it was approved.
    """
    rows = asyncio.run(read_policy_changes(path, limit=max(0, last)))
    if not rows:
        typer.echo("(no policy changes recorded yet)")
        return
    typer.echo("Doberman policy-change ledger")
    typer.echo("=" * 32)
    for row in rows:
        status = "approved" if row["approved"] else "DENIED"
        typer.echo(
            f"{row['ts']}  {row['classification']:<10} {row['rule_id']}: "
            f"{row['from_state']} -> {row['to_state']}  "
            f"[{status} via {row['approval_method']}]"
        )


@app.command("install-hooks")
def install_hooks(
    global_: bool = typer.Option(
        False, "--global", "-g", help="Install into ~/.claude/settings.json (user-wide)."
    ),
    local: bool = typer.Option(
        False, "--local", help="Install into .claude/settings.local.json (project-local)."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Wire Doberman's PreToolUse and PostToolUse hooks into a Claude Code settings.json.

    Idempotent - safe to run more than once.  Default scope is the project-level
    ``.claude/settings.json``; use ``--global`` for the user-wide file or
    ``--local`` for ``.claude/settings.local.json``.
    """
    from doberman.hosthooks.install import (
        load_settings,
        merge_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    scope = "global" if global_ else ("local" if local else "project")
    settings_path = resolve_settings_path(scope, path)

    try:
        current = load_settings(settings_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    merged = merge_doberman_hooks(current)

    if dry_run:
        typer.echo(f"[dry-run] target: {settings_path}")
        typer.echo("[dry-run] would add:")
        typer.echo("  PreToolUse   -> doberman hook pre")
        typer.echo("  PostToolUse  -> doberman hook post")
        typer.echo("  SessionStart -> doberman dashboard")
        return

    write_settings(settings_path, merged)
    typer.echo(f"wrote {settings_path}")
    typer.echo("Doberman will now gate every tool call in this project.")
    typer.echo("The session dashboard will print at the start of every session.")


@app.command("uninstall-hooks")
def uninstall_hooks(
    global_: bool = typer.Option(
        False, "--global", "-g", help="Remove from ~/.claude/settings.json (user-wide)."
    ),
    local: bool = typer.Option(
        False, "--local", help="Remove from .claude/settings.local.json (project-local)."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Remove Doberman's PreToolUse and PostToolUse hooks from a Claude Code settings.json.

    Idempotent - safe to run even when hooks are not present.  Non-Doberman hooks
    and every other setting are left untouched.
    """
    from doberman.hosthooks.install import (
        _is_doberman_group,
        load_settings,
        remove_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    scope = "global" if global_ else ("local" if local else "project")
    settings_path = resolve_settings_path(scope, path)

    try:
        current = load_settings(settings_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    # Detect whether any Doberman entries exist before removing.
    hooks_section = current.get("hooks") or {}
    had_doberman = any(
        _is_doberman_group(g)
        for groups in hooks_section.values()
        if isinstance(groups, list)
        for g in groups
    )

    if not had_doberman:
        typer.echo("No Doberman hooks found - nothing to remove.")
        return

    cleaned = remove_doberman_hooks(current)

    if dry_run:
        typer.echo(f"[dry-run] target: {settings_path}")
        typer.echo("[dry-run] would remove:")
        typer.echo("  PreToolUse   -> doberman hook pre")
        typer.echo("  PostToolUse  -> doberman hook post")
        typer.echo("  SessionStart -> doberman dashboard")
        return

    write_settings(settings_path, cleaned)
    typer.echo(f"wrote {settings_path}")
    typer.echo("Doberman hooks removed.")


@app.command()
def setup(
    yes: bool = typer.Option(False, "--yes", "-y", help="Accept all defaults with no prompts."),
    mode_name: str = typer.Option(
        None, "--mode", "-m", help="Security mode (light/balanced/strict/paranoid)."
    ),
    global_: bool = typer.Option(
        False, "--global", "-g", help="Install hooks into ~/.claude/settings.json."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
) -> None:
    """Friendly first-run wizard: choose your security posture and wire Claude Code hooks.

    Walks through alertness mode, preference tuning, and automatic hook installation.
    Pass ``--yes`` for a fully non-interactive run (useful for CI or scripting).
    """
    from doberman.hosthooks.install import (
        load_settings,
        merge_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )
    from doberman.hosthooks.setup import PROFILE_CHOICES, mode_menu_lines, parse_mode_choice
    from doberman.policy.preferences import vector_for

    # ------------------------------------------------------------------
    # a. Welcome
    # ------------------------------------------------------------------
    typer.echo("")
    typer.echo("Welcome to Doberman setup!")
    typer.echo(
        "Doberman sits between your coding agent and its tools, turning every "
        "meaningful action into a risk-based allow / authenticate / block decision."
    )
    typer.echo("")

    # ------------------------------------------------------------------
    # b. Alertness / mode
    # ------------------------------------------------------------------
    if mode_name is not None:
        # Caller pre-selected a mode; validate it immediately.
        try:
            chosen_mode = parse_mode_choice(mode_name)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from exc
    elif yes:
        from doberman.policy.modes import SecurityMode

        chosen_mode = SecurityMode.balanced
    else:
        typer.echo("-- Security mode ---------------------------------------")
        for line in mode_menu_lines():
            typer.echo(line)
        typer.echo("")
        raw = typer.prompt("Choose a mode (name or number)", default="balanced")
        try:
            chosen_mode = parse_mode_choice(raw)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from exc

    # Save the chosen mode.
    try:
        save_mode(chosen_mode.value, path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    # ------------------------------------------------------------------
    # c. Guardrails / preferences
    # ------------------------------------------------------------------
    preset_vector = vector_for(chosen_mode)
    tune_prefs = False

    if not yes:
        typer.echo("")
        typer.echo("-- Preference tuning -----------------------------------")
        typer.echo(
            f"The {chosen_mode.value!r} preset applies these weights: "
            + "  ".join(f"{n}={getattr(preset_vector, n):.2f}" for n in DIMENSIONS)
        )
        tune_prefs = typer.confirm("Tune individual weights? (advanced)", default=False)

    if tune_prefs:
        vector = preset_vector
        typer.echo("Enter a weight in [0, 1] for each dimension (press Enter to keep current):")
        for dim in DIMENSIONS:
            current = getattr(vector, dim)
            raw_w = typer.prompt(f"  {dim} [{current:.2f}]", default=str(current))
            try:
                vector = vector.with_weight(dim, float(raw_w))
            except (KeyError, ValueError) as exc:
                typer.echo(f"  warning: {exc} - keeping {current:.2f}")
        save_preferences(vector, path)
    else:
        # Persist the preset so load_preferences returns the mode's preset explicitly.
        save_preferences(preset_vector, path)

    # ------------------------------------------------------------------
    # d. Profile (informational only - no persistence)
    # ------------------------------------------------------------------
    profile_answer: str | None = None
    if not yes:
        typer.echo("")
        typer.echo("-- Agent profile (informational) -----------------------")
        typer.echo(
            "This helps you think about your setup. "
            "Doberman infers the app type automatically at runtime."
        )
        choices_str = " / ".join(PROFILE_CHOICES)
        profile_answer = typer.prompt(
            f"What does this agent mostly do? [{choices_str}]",
            default="coding",
        )

    # ------------------------------------------------------------------
    # e. Hook installation scope
    # ------------------------------------------------------------------
    if global_:
        scope = "global"
    elif yes:
        scope = "project"
    else:
        typer.echo("")
        typer.echo("-- Hook installation -----------------------------------")
        use_global = typer.confirm(
            "Install hooks globally (~/.claude/settings.json)?",
            default=False,
        )
        scope = "global" if use_global else "project"

    settings_path = resolve_settings_path(scope, path)

    try:
        current = load_settings(settings_path)
    except ValueError as exc:
        typer.echo(f"error: could not read existing settings: {exc}", err=True)
        raise typer.Exit(2) from exc

    merged = merge_doberman_hooks(current)

    try:
        write_settings(settings_path, merged)
    except OSError as exc:
        typer.echo(f"error: could not write {settings_path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    # ------------------------------------------------------------------
    # f. Summary
    # ------------------------------------------------------------------
    typer.echo("")
    typer.echo("-- Setup complete ------------------------------------------")
    typer.echo(f"Mode:       {chosen_mode.value}")
    typer.echo(
        f"Prefs:      {'custom (tuned)' if tune_prefs else 'preset defaults for ' + chosen_mode.value}"
    )
    if profile_answer is not None:
        typer.echo(f"Profile:    {profile_answer} (noted - not persisted; inferred at runtime)")
    typer.echo(f"Hooks:      written to {settings_path}")
    typer.echo("")
    typer.echo("Doberman is now active.")
    typer.echo("Restart your Claude Code session to pick up the hooks.")
    typer.echo("Next steps: `doberman 2fa setup`  |  `doberman status`")


@app.command()
def dashboard() -> None:
    """Print the device-global session-guard summary and exit.

    Reads the lifetime rollup at ``~/.doberman/metrics.db`` (every decision on
    this device, across all repos/sessions, increments it - see
    ``doberman.storage.device_metrics``) and prints a compact panel. This is a
    print-and-exit command, not an interactive dashboard: it is wired as a
    Claude Code SessionStart hook (``doberman install-hooks``), so it must
    never block or crash a session - it always exits 0 and never raises.
    """
    try:
        from doberman.storage.device_metrics import read_metrics, render_dashboard

        typer.echo(render_dashboard(read_metrics()))
    except Exception:  # noqa: BLE001, S110 — a dashboard must never break session start
        pass
    raise typer.Exit(0)


@app.command()
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
