"""The ``doberman`` CLI entry point (Feature 5).

Currently exposes ``doberman scan`` — a read-only capability/risk-map report for
the current repository. More commands (status, init, policy) arrive with later
features.
"""

import typer

from doberman import __version__
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map

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
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
