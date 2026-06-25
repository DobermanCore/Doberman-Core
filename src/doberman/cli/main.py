"""The ``doberman`` CLI entry point (Features 5–7).

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

app = typer.Typer(
    help="Doberman — adaptive authorization layer for coding agents.",
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
    propagation, and — defense in depth — strip any stdout handler from the root logger so a
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
    # `log`, `status`, `scan`, …) don't pay the cost of loading the subjective
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
    except Exception as exc:  # noqa: BLE001 — surface a clean stderr error, never a raw traceback
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
            tags.append("N/A — capability absent")
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
    matches (if any). Weights tune SUBJECTIVE step-up propensity only — the
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


@app.command()
def status(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show the active role, security mode, and policy summary."""
    role = load_active_role(path)
    doc = load_policy(path)
    typer.echo("Doberman status")
    typer.echo("=" * 32)
    typer.echo(f"Role:   {role.name if role else '(none — role enforcement off)'}")
    typer.echo(f"Mode:   {load_mode(path)}  (of: {', '.join(m.value for m in SecurityMode)})")
    vector = load_preferences(path)
    typer.echo(
        "Prefs:  "
        + "  ".join(f"{name}={getattr(vector, name):.2f}" for name in DIMENSIONS)
        + f"  (preset: {preset_name(vector) or 'custom'})"
    )
    if doc is None:
        typer.echo("Policy: (none saved — run `doberman review --yes`)")
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


@hook_app.command("pre")
def hook_pre() -> None:
    """Claude Code PreToolUse hook — gate one tool call (allow / ask / deny).

    Reads the harness hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS — Doberman is raise-only and never
    suppresses the harness's own prompts). Runs only the fast deterministic
    objective floor (no numpy/scipy/river), so it adds minimal latency to every
    tool call, and fails closed (deny) on any malformed input or engine error.

    Wire it into Claude Code's settings (a later slice adds `doberman
    install-hooks` to do this for you).
    """
    # Imported here, not at module scope, so the other CLI commands don't load
    # the decision path on every `--help`/`status`/`log` invocation.
    from doberman.hosthooks.claude_code import run_pre_hook

    out = run_pre_hook(sys.stdin.read())
    if out is not None:
        # The harness parses stdout as JSON; write ONLY the decision there.
        sys.stdout.write(out)
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

    Every row is already redacted — a path class, reason codes, the verdict, and
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

    Reads as classifications and habits — counts, verdict mix, most-touched path
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
            typer.echo(f"  {cls}  ×{count}")
    typer.echo(f"Distinct secrets seen (count only, never stored): {summary['secrets_seen']}")


@app.command("policy-history")
def policy_history(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N changes."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show the append-only policy-change ledger (newest first).

    Records every classified change — strengthen / weaken / neutral — **including
    denied weakening attempts** (the poisoning signal). Each row shows the rule,
    the before→after states, the classification, and how it was approved.
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
            f"{row['from_state']} → {row['to_state']}  "
            f"[{status} via {row['approval_method']}]"
        )


@app.command()
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
