"""The ``doberman`` CLI entry point (Features 5–7).

Exposes ``doberman scan`` (risk map), ``review`` / ``mode`` / ``status``
(policy), and the Feature 7 auth surface: ``doberman 2fa setup`` (TOTP
enrollment) and ``doberman revoke`` (revoke a role elevation). ``status`` also
lists currently-active elevations.
"""

import asyncio
import json
from datetime import datetime, timezone

import typer

from doberman import __version__
from doberman.auth import totp
from doberman.config import load_active_role, load_mode, load_policy, save_mode, save_policy
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.policy.checklist import recommend_policy
from doberman.policy.modes import SecurityMode
from doberman.storage.db import active_elevations, revoke_elevation
from doberman.storage.log import memory_summary, read_decisions

app = typer.Typer(
    help="Doberman — adaptive authorization layer for coding agents.",
    no_args_is_help=True,
    add_completion=False,
)

twofa_app = typer.Typer(help="Two-factor (TOTP) enrollment.", no_args_is_help=True)
app.add_typer(twofa_app, name="2fa")


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


@app.command()
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
