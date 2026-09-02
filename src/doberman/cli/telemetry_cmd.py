"""Typer commands and small CLI-only wiring for default-on, opt-out telemetry."""

from __future__ import annotations

import typer

from doberman.render import wrap_detail

telemetry_app = typer.Typer(
    help="Anonymous usage telemetry (on by default; `doberman telemetry off` stops it).",
    no_args_is_help=True,
)

_NESTED_GROUPS = ("2fa", "password", "taint", "tools", "memory", "role")
_EXCLUDED = {"hook", "serve", "telemetry"}


def _record_command(command: str | None, *, suppress_notice: bool = False) -> None:
    if not command or command in _EXCLUDED:
        return
    from doberman import telemetry

    if not suppress_notice:
        notice = telemetry.first_run_notice()
        if notice:
            typer.echo(notice, err=True)
    telemetry.capture("cli_command", {"command": command})
    telemetry.maybe_send_usage_summary()


def record_root_command(command: str | None) -> None:
    """Record a top-level command unless a nested callback owns its full name.

    ``setup`` suppresses the generic first-run notice here (item 3) - its own
    wizard shows a dedicated ``-- Telemetry --`` section a few lines later, so
    printing the generic notice too would mention telemetry a 3rd time in one
    run. The command is still recorded and the notice's "seen" flag is still
    consumed inside the wizard's own telemetry step, so no *later* command in
    the session shows it again.
    """
    if command not in _NESTED_GROUPS:
        _record_command(command, suppress_notice=command == "setup")


def _subcommand_callback(group: str):
    def callback(ctx: typer.Context) -> None:
        suffix = f".{ctx.invoked_subcommand}" if ctx.invoked_subcommand else ""
        _record_command(f"{group}{suffix}")

    return callback


def register_cli_telemetry(root_app: typer.Typer, *sub_apps: typer.Typer) -> None:
    """Register the telemetry group and nested command callbacks."""
    root_app.add_typer(telemetry_app, name="telemetry", rich_help_panel="Advanced")
    for group, sub_app in zip(_NESTED_GROUPS, sub_apps, strict=True):
        sub_app.callback()(_subcommand_callback(group))


#: Reused verbatim so the explanation reads the same whether or not a question
#: follows it (``--yes`` never asks, but still says what telemetry sends).
#: "reason payloads" is glossed inline (item 10) since it's jargon with no
#: nearby definition, unlike "possession factor"/"trifecta" elsewhere in the
#: wizard, which already carry one at their point of use.
TELEMETRY_EXPLANATION = (
    "Counts and command names only. Never paths, prompts, secrets, or reason "
    "payloads (the structured why-blocked details). See "
    "https://github.com/DobermanCore/Doberman-Core/blob/main/docs/TELEMETRY.md."
)


def telemetry_summary_line() -> str:
    """One-line consent summary ("Telemetry: on/off"), reused by the setup
    wizard's ``--yes`` path (item 3) so it never needs the full explanation."""
    from doberman import telemetry

    if telemetry.is_enabled():
        return "Telemetry: on - anonymous usage counts; `doberman telemetry off` to opt out"
    return "Telemetry: off"


def configure_setup_consent(non_interactive: bool) -> None:
    """Ask the setup-only consent question; ``--yes`` prints a compact on/off
    summary instead.

    The caller is expected to have already printed a section header (e.g.
    ``_section("Telemetry")``). Interactive: print the full explanation, then
    ask. ``--yes``: skip the explanation (the wizard mentions telemetry at
    most twice per run - item 3 - and the ``Also:`` epilogue line already
    covers the opt-out pointer) and print the one-line on/off summary instead;
    ``telemetry.first_run_notice()`` is still called for its side effect only
    (marks the notice "seen" so no later command in the session prints it),
    discarding the text it returns since the summary line already says it.
    """
    from doberman import telemetry

    if non_interactive:
        telemetry.first_run_notice()
        for line in wrap_detail(telemetry_summary_line(), indent=0, hang=2):  # item 4
            typer.echo(line)
        return
    for line in wrap_detail(TELEMETRY_EXPLANATION, indent=0):
        typer.echo(line)
    if typer.confirm("Send anonymous usage stats to help improve Doberman?", default=True):
        telemetry.enable()
    else:
        telemetry.disable()


def capture_setup_completed(
    mode: str, hosts: list[str], claude_scope: str, non_interactive: bool
) -> None:
    """Emit the allowlisted setup outcome after the chosen hosts are wired.

    ``hosts`` is the ordered list of host keys the wizard wired (claude / codex /
    mcp / openclaw). ``claude_scope`` is the Claude settings scope ("project" /
    "global") when "claude" was one of them, else the literal string "none".
    Reuses the existing allowlisted ``setup_completed`` properties (``host``,
    ``global_install``) rather than adding new ones.
    """
    from doberman import telemetry

    telemetry.capture(
        "setup_completed",
        {
            "mode": mode,
            "host": ",".join(hosts),
            "hooks_installed": any(h in ("claude", "codex") for h in hosts),
            "global_install": claude_scope == "global",
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
