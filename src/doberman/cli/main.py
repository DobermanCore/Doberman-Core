"""The ``doberman`` CLI entry point (Features 5–7).

Exposes ``doberman scan`` (risk map), ``review`` / ``mode`` / ``status``
(policy), and the Feature 7 auth surface: ``doberman 2fa setup`` (TOTP
enrollment) and ``doberman revoke`` (revoke a role elevation). ``status`` also
lists currently-active elevations.
"""

import asyncio
import logging
import sys
from datetime import datetime, timezone

import typer
from mcp import StdioServerParameters

from doberman import __version__
from doberman.auth import totp
from doberman.config import load_active_role, load_mode, load_policy, save_mode, save_policy
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.policy.checklist import recommend_policy
from doberman.policy.modes import SecurityMode
from doberman.proxy.serve import serve_stdio
from doberman.storage.db import active_elevations, revoke_elevation

app = typer.Typer(
    help="Doberman — adaptive authorization layer for coding agents.",
    no_args_is_help=True,
    add_completion=False,
)

twofa_app = typer.Typer(help="Two-factor (TOTP) enrollment.", no_args_is_help=True)
app.add_typer(twofa_app, name="2fa")


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
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
