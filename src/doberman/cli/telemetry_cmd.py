"""Typer commands and small CLI-only wiring for default-on, opt-out telemetry."""

from __future__ import annotations

import typer

telemetry_app = typer.Typer(
    help="Anonymous usage telemetry (on by default; `doberman telemetry off` stops it).",
    no_args_is_help=True,
)

_NESTED_GROUPS = ("2fa", "password", "taint", "tools", "memory", "role")
_EXCLUDED = {"hook", "serve", "telemetry"}


def _record_command(command: str | None) -> None:
    if not command or command in _EXCLUDED:
        return
    from doberman import telemetry

    notice = telemetry.first_run_notice()
    if notice:
        typer.echo(notice, err=True)
    telemetry.capture("cli_command", {"command": command})
    telemetry.maybe_send_usage_summary()


def record_root_command(command: str | None) -> None:
    """Record a top-level command unless a nested callback owns its full name."""
    if command not in _NESTED_GROUPS:
        _record_command(command)


def _subcommand_callback(group: str):
    def callback(ctx: typer.Context) -> None:
        suffix = f".{ctx.invoked_subcommand}" if ctx.invoked_subcommand else ""
        _record_command(f"{group}{suffix}")

    return callback


def register_cli_telemetry(root_app: typer.Typer, *sub_apps: typer.Typer) -> None:
    """Register the telemetry group and nested command callbacks."""
    root_app.add_typer(telemetry_app, name="telemetry")
    for group, sub_app in zip(_NESTED_GROUPS, sub_apps, strict=True):
        sub_app.callback()(_subcommand_callback(group))


def configure_setup_consent(non_interactive: bool) -> None:
    """Ask the setup-only consent question; ``--yes`` keeps the default (on) and prints the notice."""
    from doberman import telemetry

    if non_interactive:
        notice = telemetry.first_run_notice()
        if notice:
            typer.echo(notice, err=True)
        return
    typer.echo("")
    typer.echo(
        "Counts and command names only. Never paths, prompts, secrets, or reason payloads. "
        "See docs/TELEMETRY.md."
    )
    if typer.confirm("Send anonymous usage stats to help improve Doberman?", default=True):
        telemetry.enable()
    else:
        telemetry.disable()


def capture_setup_completed(mode: str, scope: str, non_interactive: bool) -> None:
    """Emit the allowlisted setup outcome after hooks are installed."""
    from doberman import telemetry

    telemetry.capture(
        "setup_completed",
        {
            "mode": mode,
            "host": "claude",
            "hooks_installed": True,
            "global_install": scope == "global",
            "source": "yes" if non_interactive else "wizard",
        },
    )


@telemetry_app.command("on")
def telemetry_on() -> None:
    """Enable anonymous usage telemetry."""
    from doberman import telemetry

    state = telemetry.enable()
    typer.echo(f"Telemetry enabled. Distinct id: {state.distinct_id}")


@telemetry_app.command("off")
def telemetry_off() -> None:
    """Disable anonymous usage telemetry."""
    from doberman import telemetry

    telemetry.disable()
    typer.echo("Telemetry disabled.")


@telemetry_app.command("status")
def telemetry_status() -> None:
    """Show consent state, anonymous id, and active kill switches."""
    from doberman import telemetry

    state = telemetry.status()
    enabled = telemetry.is_enabled()
    label = "enabled" if enabled else "disabled"
    if enabled and state.consent_at is None:
        label += " (default; `doberman telemetry off` to stop)"
    typer.echo(f"Telemetry: {label}")
    typer.echo(f"Distinct id: {state.distinct_id or '(not created)'}")
    for reason in state.forced_off_reasons:
        typer.echo(f"Forced off: {reason}")
