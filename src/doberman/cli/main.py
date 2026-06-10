"""The ``doberman`` CLI entry point (Feature 5).

Currently exposes ``doberman scan`` — a read-only capability/risk-map report for
the current repository. More commands (status, init, policy) arrive with later
features.
"""

import typer

from doberman import __version__
from doberman.config import load_active_role, load_mode, load_policy, save_mode, save_policy
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.policy.checklist import recommend_policy
from doberman.policy.modes import SecurityMode

app = typer.Typer(
    help="Doberman — adaptive authorization layer for coding agents.",
    no_args_is_help=True,
    add_completion=False,
)


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


@app.command()
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
