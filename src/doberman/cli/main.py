"""The ``doberman`` CLI entry point (Features 5-7).

Exposes ``doberman scan`` (risk map), ``review`` / ``mode`` / ``status``
(policy), and local auth surfaces: ``doberman password set``, ``doberman 2fa
setup`` (optional TOTP enrollment), and ``doberman revoke`` (revoke a role
elevation). ``status`` also lists currently-active elevations.
"""

import asyncio
import importlib.util
import json
import logging
import secrets
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer

from doberman import __version__
from doberman.auth import password, totp
from doberman.auth.challenge import TIMEOUT_METHOD
from doberman.auth.provider import CliPrompter
from doberman.config import (
    CONFIG_DIR,
    MESSAGE_TONES,
    default_role_enabled,
    load_active_role,
    load_enforcement,
    load_message_tone,
    load_mode,
    load_policy,
    load_preferences,
    save_default_role_enabled,
    save_message_tone,
    save_mode,
    save_policy,
    save_preferences,
)
from doberman.demo import format_outcome_line, format_summary_table, run_demo
from doberman.discovery.mcp_scan import MCP_CONFIG_FILES, scan_mcp_configs
from doberman.discovery.scan import enumerate_capabilities, rate_capabilities, render_risk_map
from doberman.policy.checklist import recommend_policy
from doberman.policy.drift import (
    _verify_possession_factor,
    apply_change,
    apply_enforcement_change,
    apply_preferences_change,
    apply_standing_elevation,
    log_change,
    read_policy_changes,
)
from doberman.policy.friction import build_friction_report, generate_proposals
from doberman.policy.modes import SecurityMode, resolve_mode
from doberman.policy.preferences import DIMENSIONS, preset_name
from doberman.render import verdict_label, verdict_label_str
from doberman.storage.db import active_elevations, grant_elevation, revoke_elevation
from doberman.storage.exclusions import add_exclusion, is_excluded, remove_exclusion
from doberman.storage.log import memory_summary, read_decisions
from doberman.storage.memory import prune_stale_entities, reset_memory
from doberman.storage.taint import clear_taint, entity_scope, read_taint
from doberman.storage.tool_pins import approve_pin


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
)

twofa_app = typer.Typer(help="Two-factor (TOTP) enrollment.", no_args_is_help=True)
app.add_typer(twofa_app, name="2fa")

password_app = typer.Typer(
    help="Local password possession factor (the minimum lowering-gate auth).",
    no_args_is_help=True,
)
app.add_typer(password_app, name="password")

taint_app = typer.Typer(
    help="Sticky session-taint recovery (gated - requires an enrolled possession factor).",
    no_args_is_help=True,
)
app.add_typer(taint_app, name="taint")

tools_app = typer.Typer(
    help="MCP tool-schema pin management (gated re-approval).",
    no_args_is_help=True,
)
app.add_typer(tools_app, name="tools")

memory_app = typer.Typer(
    help="Learned behavioral memory: profile, gated reset, and retention pruning.",
    no_args_is_help=False,
)
app.add_typer(memory_app, name="memory")

hook_app = typer.Typer(
    help="Host-harness integration hooks (e.g. Claude Code PreToolUse/PostToolUse).",
    no_args_is_help=True,
)
app.add_typer(hook_app, name="hook")

role_app = typer.Typer(
    help="Agent role boundary (Feature 4) — the opt-in built-in default role.",
    no_args_is_help=True,
)
app.add_typer(role_app, name="role")


def _print_version_and_exit(show_version: bool) -> None:
    if show_version:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print the installed Doberman version and exit.",
        callback=_print_version_and_exit,
        is_eager=True,
    ),
) -> None:
    pass


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


#: Shown once, only to a human at a terminal, before `serve` blocks on stdin.
#: Run bare, the proxy logs two lines and then goes silent forever waiting for a
#: client's JSON-RPC — indistinguishable from a hang, and easy to read as "serve
#: is supposed to start my agent and didn't". It starts nothing: an MCP client
#: spawns *it*. Never write this to stdout; stdout IS the MCP channel.
_SERVE_WAITING_HINT = (
    "waiting for an MCP client to connect on stdin - this command does not start your agent. "
    "Register it once (`claude mcp add doberman -- doberman serve -- <your tool server>`), then "
    "start the agent separately. For Claude Code, `doberman setup` instead wires hooks that gate "
    "every tool call with no MCP reconfig."
)


def _stderr_is_tty() -> bool:
    """Whether a human is watching stderr. A seam: a CLI test runner replaces
    ``sys.stderr`` with a non-tty capture, so this is the patch point."""
    return sys.stderr.isatty()


@app.command(
    rich_help_panel="Advanced",
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

    This does not launch your agent - the agent's MCP client spawns this process. Run bare in a
    terminal it just waits on stdin for a client.
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
    if _stderr_is_tty():  # a human ran it; a client-spawned process gets a pipe
        typer.echo(f"doberman: {_SERVE_WAITING_HINT}", err=True)
    try:
        asyncio.run(serve_stdio(params, repo_root=path))
    except Exception as exc:  # noqa: BLE001 - surface a clean stderr error, never a raw traceback
        typer.echo(f"error: doberman serve failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command(rich_help_panel="Advanced")
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Repository root to scan."),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress human-readable stdout (exit code unchanged; useful for CI).",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one deterministic JSON document on stdout instead of the risk map.",
    ),
    mcp: bool = typer.Option(
        False,
        "--mcp",
        help="Statically scan known repository MCP configs for suspicious patterns.",
    ),
) -> None:
    """Show a read-only risk map of the agent's capabilities and sensitive surface.

    Sensitive files are detected by name only and never read; nothing is written.
    Tool-derived capabilities require a live proxy session and are omitted here.
    """
    capabilities = rate_capabilities(enumerate_capabilities(tools=[], repo_root=path))
    mcp_findings = scan_mcp_configs(path) if mcp else []
    mcp_files = (
        [name for name in MCP_CONFIG_FILES if (Path(path) / Path(name)).is_file()] if mcp else []
    )
    if as_json:
        # Stable schema for scripts/editor integrations (#178).
        payload = {
            "version": 1,
            "path": path,
            "capabilities": [
                {
                    "name": c.name,
                    "category": c.category,
                    "present": c.present,
                    "risk": (c.risk.value if c.risk is not None else None),
                    "evidence": list(c.evidence),
                }
                for c in sorted(capabilities, key=lambda x: (x.category, x.name))
            ],
        }
        if mcp:
            payload["mcp"] = {
                "findings": [
                    {
                        "server": finding.server,
                        "source_file": finding.source_file,
                        "category": finding.category,
                        "pattern_class": finding.pattern_class,
                        "risk": finding.risk.value,
                    }
                    for finding in mcp_findings
                ],
                "files_scanned": mcp_files,
            }
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    if not quiet:
        output = render_risk_map(capabilities)
        if mcp:
            lines = ["", "MCP configuration admission scan", "=" * 32]
            if mcp_findings:
                lines.extend(
                    f"[{finding.risk.value.upper():^8}] {finding.source_file} "
                    f"{finding.server} ({finding.category}/{finding.pattern_class})"
                    for finding in mcp_findings
                )
            else:
                lines.append("No suspicious MCP configuration patterns found.")
            output = "\n".join([output, *lines])
        typer.echo(output)


@app.command(rich_help_panel="Policy")
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
        typer.echo(f"{box} {verdict_label(item.verdict)} {item.id}{suffix}")
    typer.echo(f"\nMode: {doc.mode}")

    if yes:
        save_policy(doc, path)
        typer.echo(f"\nSaved policy to {path}/.doberman/policies.yaml")
    else:
        typer.echo("\n(read-only; re-run with --yes to save)")


def _apply_mode_change(
    name: str, path: str, reason: str, *, establish_ok: bool = False
) -> str | None:
    """Resolve ``name``, gate any weakening behind a possession factor, then persist it.

    The mode dial is now gated at parity with the enforcement dial:
    lowering strictness (a downgrade on the paranoid>strict>balanced>light
    scale) is a ``weaken`` and must clear a possession factor — a 2FA code if
    enrolled, otherwise the Doberman password set via ``doberman password set`` —
    before it is persisted. Raising stays frictionless: ``apply_change`` auto-approves
    a strengthen with no prompt. A no-op (unchanged mode) skips the gate/ledger entirely.
    Every attempt (incl. denials) is recorded to the append-only ledger. Returns
    ``None`` when the gate denies the change — fail closed, nothing persisted.

    ``establish_ok`` (first-run onboarding via ``doberman setup``) writes the
    INITIAL posture freely when no policy is persisted yet — choosing a starting
    mode is not weakening an existing one, and 2FA is enrolled later in the
    wizard. The change is still recorded to the ledger. Once a policy exists,
    even a setup re-run falls through to the gate, so neither ``setup`` nor
    ``mode`` can bypass the possession factor on a lowering.
    """
    old = load_mode(path)
    new = resolve_mode(name).value  # raises ValueError for an unknown mode
    if old == new:
        return save_mode(name, path)
    if establish_ok and load_policy(path) is None:
        asyncio.run(log_change({"mode": old}, {"mode": new}, reason, repo_root=path))
        return save_mode(name, path)
    outcome = asyncio.run(apply_change({"mode": old}, {"mode": new}, reason, repo_root=path))
    if not outcome.approved:
        return None
    return save_mode(name, path)


@app.command(rich_help_panel="Policy")
def mode(
    name: str = typer.Argument(None, help="Mode to set (light/balanced/strict/paranoid)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the security strength mode.

    Lowering strictness requires a possession factor — a 2FA code if enrolled,
    otherwise your Doberman password (set via `doberman password set`). Raising
    is always frictionless.
    """
    if name is None:
        typer.echo(load_mode(path))
        return
    try:
        saved = _apply_mode_change(name, path, "doberman mode CLI")
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if saved is None:
        typer.echo("error: mode change denied; unchanged", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"mode set to {saved}")


_ENFORCEMENT_STATES = ("enforce", "monitor", "off")


@app.command(rich_help_panel="Policy")
def enforcement(
    state: str = typer.Argument(None, help="Enforcement state to set (enforce/monitor/off)."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the enforcement dial (enforce / monitor / off).

    Orthogonal to the strictness ``mode``: this decides whether Doberman *acts*
    on a discretionary verdict (``enforce``, the default) or only observes
    (``monitor`` records what would have happened; ``off`` skips the discretionary
    layer). The objective floor (secret exfil, destructive commands, ...) stays
    live in every state.

    Turning the dial DOWN is a weaken: it is confirmed -- plus the strongest
    enrolled possession factor (a 2FA code if enrolled, else the local password)
    -- and recorded in the append-only policy-change ledger. With neither factor
    enrolled the change fails closed (run ``doberman password set`` first).
    Re-arming (``-> enforce``) is a strengthen and applies automatically. A
    softened state is honored only while the ledger confirms it; hand-editing
    ``policies.yaml`` is clamped back to ``enforce`` (fail closed). With no
    argument, prints the current on-disk state.
    """
    current, _expires, _revert = load_enforcement(path)
    if state is None:
        typer.echo(current)
        return
    new = state.strip().lower()
    if new not in _ENFORCEMENT_STATES:
        typer.echo(
            f"error: unknown enforcement state {state!r}; "
            f"choose one of {', '.join(_ENFORCEMENT_STATES)}",
            err=True,
        )
        raise typer.Exit(code=2)
    if new == current:
        typer.echo(f"enforcement already {current}")
        return
    # Route through the gated chokepoint: it confirms a soften behind the
    # strongest enrolled possession factor (fails closed if none is enrolled),
    # auto-approves a re-arm, and records every attempt to the ledger. Persist the
    # new state ONLY when it approved, and persist the exact fields the ledger just
    # recorded so the read-side effective_enforcement clamp confirms the soften.
    outcome = asyncio.run(
        apply_enforcement_change(
            {"enforcement": current},
            {"enforcement": new},
            "doberman enforcement CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: enforcement change denied; unchanged", err=True)
        raise typer.Exit(code=1)
    save_policy((load_policy(path) or recommend_policy()).with_enforcement(new), path)
    typer.echo(f"enforcement set to {new}")


@role_app.command("enable-default")
def role_enable_default(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Turn on the built-in opt-in least-privilege default role (D1).

    Activates the packaged ``"default"`` role (see ``builtin_roles.yaml``)
    whenever this repo has no explicit ``.doberman/role.yaml`` — an explicit
    role file always takes precedence. Enabling is a strengthen (adds a role
    boundary that wasn't enforced before) and applies immediately, no gate.
    """
    was = default_role_enabled(path)
    if was:
        typer.echo("the default role is already enabled")
        return
    # A strengthen: apply_change auto-approves (no gate) and still records the
    # attempt to the append-only ledger.
    asyncio.run(
        apply_change(
            {"default_role_enabled": was},
            {"default_role_enabled": True},
            "doberman role enable-default CLI",
            repo_root=path,
        )
    )
    save_default_role_enabled(True, path)
    typer.echo("the built-in default role is now enabled (used when no role.yaml is set)")


@role_app.command("disable-default")
def role_disable_default(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Turn off the built-in opt-in least-privilege default role (D1).

    Disabling removes an active role boundary — a ``weaken`` — so it is gated
    behind the strongest enrolled possession factor (a 2FA code if enrolled,
    otherwise the Doberman password set via ``doberman password set``); with
    neither enrolled the change fails closed (denied, nothing changes).
    """
    was = default_role_enabled(path)
    if not was:
        typer.echo("the default role is already disabled")
        return
    outcome = asyncio.run(
        apply_change(
            {"default_role_enabled": was},
            {"default_role_enabled": False},
            "doberman role disable-default CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: disabling the default role was denied; unchanged", err=True)
        raise typer.Exit(code=1)
    save_default_role_enabled(False, path)
    typer.echo("the built-in default role is now disabled")


@app.command(rich_help_panel="Policy")
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
    objective hard-block floor is unaffected by every weight. Lowering a
    weight requires a possession factor — a 2FA code if enrolled, otherwise
    your Doberman password (set via `doberman password set`). Raising is always frictionless.
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
    current = load_preferences(path)
    try:
        updated = current.with_weight(dimension, value)
    except (KeyError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    outcome = asyncio.run(
        apply_preferences_change(
            current.to_mapping(),
            updated.to_mapping(),
            "doberman prefs CLI",
            repo_root=path,
        )
    )
    if not outcome.approved:
        typer.echo("error: preference change denied; unchanged", err=True)
        raise typer.Exit(code=1)
    save_preferences(updated, path)
    typer.echo(f"{dimension} set to {value:.2f}")


@app.command("message-tone", rich_help_panel="Policy")
def message_tone(
    tone: str = typer.Argument(None, help=f"New tone ({', '.join(MESSAGE_TONES)})."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show or set the AUTH challenge message tone (S1; cosmetic display only).

    With no argument, prints the active tone. "human" (the default) renders a
    plain, friendly challenge; "technical" keeps the original detailed format.
    This never changes what is evaluated, blocked, or logged — reason codes
    stay on every decision either way — so, unlike `prefs`/`mode`, it needs no
    possession factor to change.
    """
    if tone is None:
        typer.echo(load_message_tone(path))
        return
    try:
        saved = save_message_tone(tone, path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"message tone set to {saved}")


def _hook_install_states(path: str) -> list[tuple[str, str, bool]]:
    """Per-scope Doberman hook install state (delegates to the shared helper).

    Kept as a thin wrapper so ``status`` (and its tests) keep a stable name; the
    logic lives in :func:`doberman.hosthooks.install.hook_install_states` so
    ``doctor`` can reuse it without importing the CLI module.
    """
    from doberman.hosthooks.install import hook_install_states

    return hook_install_states(path)


def _status_payload(path: str) -> dict:
    """Collect the same redacted data the text and JSON status views share.

    Nothing secret-shaped is included: enrollment is a boolean, elevations carry
    ids/scopes/expiry only, decisions carry ts/verdict/reason codes only.
    """
    role = load_active_role(path)
    doc = load_policy(path)
    vector = load_preferences(path)
    mode = load_mode(path)
    tone = load_message_tone(path)
    twofa = totp.is_enrolled()
    password_enrolled = password.is_enrolled()
    grants = asyncio.run(active_elevations(path, datetime.now(timezone.utc)))
    taints = asyncio.run(read_taint(path, entity_scope(path)))
    hook_states = _hook_install_states(path)
    recent_rows = asyncio.run(read_decisions(path, limit=5))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    missed_challenges = 0
    for row in asyncio.run(read_decisions(path, limit=200)):
        if row.get("auth_result") != TIMEOUT_METHOD:
            continue
        try:
            occurred_at = datetime.fromisoformat(row["ts"])
            if occurred_at.tzinfo is not None and occurred_at >= cutoff:
                missed_challenges += 1
        except (TypeError, ValueError):
            continue

    policy: dict | None
    if doc is None:
        policy = None
    else:
        enabled = sum(1 for it in doc.items if it.enabled)
        policy = {"enabled": enabled, "total": len(doc.items)}

    recent_decisions: list[dict] = []
    for row in recent_rows:
        try:
            reasons = json.loads(row["reason_codes_json"] or "[]")
        except json.JSONDecodeError:
            reasons = []
        recent_decisions.append(
            {
                "ts": row["ts"],
                "final_verdict": row["final_verdict"],
                "reason_codes": reasons,
            }
        )

    return {
        "version": 1,
        "path": path,
        "doberman_version": __version__,
        "role": role.name if role else None,
        "mode": mode,
        "message_tone": tone,
        "prefs": {name: getattr(vector, name) for name in DIMENSIONS},
        "prefs_preset": preset_name(vector) or "custom",
        "policy": policy,
        "twofa": twofa,
        "password": password_enrolled,
        "elevations": [
            {
                "id": grant.id,
                "scope_glob": grant.scope_glob,
                "expires_at": grant.expires_at.isoformat(),
                "single_use": grant.single_use,
            }
            for grant in grants
        ],
        "taint": dict(taints) if taints else {},
        "hooks": [
            {"scope": scope, "path": settings_path, "installed": installed}
            for scope, settings_path, installed in hook_states
        ],
        "excluded_from_global": is_excluded(path),
        "recent_decisions": recent_decisions,
        "missed_challenges_24h": missed_challenges,
    }


def _render_status_text(payload: dict) -> None:
    """Human view: one blank line between each status block."""
    modes = ", ".join(m.value for m in SecurityMode)
    typer.echo("Doberman status")
    typer.echo("=" * 32)
    typer.echo(f"Version: {payload['doberman_version']}")
    typer.echo("")

    role = payload["role"]
    typer.echo(f"Role:   {role if role else '(none - role enforcement off)'}")
    typer.echo("")

    typer.echo(f"Mode:   {payload['mode']}  (of: {modes})")
    typer.echo("")

    typer.echo(f"Messages: {payload['message_tone']}  (set via `doberman message-tone`)")
    typer.echo("")

    prefs = payload["prefs"]
    typer.echo(
        "Prefs:  "
        + "  ".join(f"{name}={prefs[name]:.2f}" for name in DIMENSIONS)
        + f"  (preset: {payload['prefs_preset']})"
    )
    typer.echo("")

    policy = payload["policy"]
    if policy is None:
        typer.echo("Policy: (none saved - run `doberman review --yes`)")
    else:
        typer.echo(f"Policy: {policy['enabled']}/{policy['total']} items enabled")
    typer.echo("")

    twofa_status = "yes" if payload["twofa"] else "no"
    typer.echo(f"2FA:    {twofa_status} (optional; run `doberman 2fa setup`)")
    typer.echo("")

    enrolled = "yes" if payload["password"] else "no (run `doberman password set`)"
    typer.echo(f"Password: {enrolled}")
    typer.echo("")

    elevations = payload["elevations"]
    if not elevations:
        typer.echo("Elevations: (none active)")
    else:
        typer.echo(f"Elevations: {len(elevations)} active")
        for grant in elevations:
            kind = "single-use" if grant["single_use"] else "reusable"
            typer.echo(
                f"  {grant['id']}  {grant['scope_glob']}  (expires {grant['expires_at']}; {kind})"
            )
    typer.echo("")

    taint = payload["taint"]
    if not taint:
        typer.echo("Taint: (none)")
    else:
        typer.echo(f"Taint: {', '.join(f'{kind}={count}' for kind, count in taint.items())}")
    typer.echo("")

    typer.echo("Hooks:")
    for hook in payload["hooks"]:
        state = "installed" if hook["installed"] else "not installed"
        typer.echo(f"  {hook['scope']:<8} {hook['path']}  [{state}]")
    if payload.get("excluded_from_global"):
        typer.echo("  excluded from global/Codex-user hooks (run `doberman install-hooks` to undo)")
    typer.echo("")

    typer.echo("Recent decisions:")
    recent = payload["recent_decisions"]
    if not recent:
        typer.echo("  (no decisions recorded yet)")
    else:
        for row in recent:
            reasons = ", ".join(row["reason_codes"]) or "-"
            typer.echo(f"  {row['ts']}  {verdict_label_str(row['final_verdict'])}  {reasons}")

    missed = payload["missed_challenges_24h"]
    if missed:
        typer.echo("")
        typer.echo(f"warning: {missed} challenge(s) auto-denied in the last 24h - see doberman log")


@app.command(rich_help_panel="Daily")
def status(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one deterministic JSON document on stdout instead of the sectioned text view.",
    ),
) -> None:
    """Show the active role, security mode, policy summary, hook install state,
    taint state, and the most recent decisions."""
    payload = _status_payload(path)
    if as_json:
        # Same style as ``scan --json`` / ``doctor --json`` (#178 / #179).
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    _render_status_text(payload)


@app.command(rich_help_panel="Getting started")
def doctor(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Emit one JSON document on stdout; health exit codes are unchanged.",
    ),
) -> None:
    """Run a read-only health self-check and print a green/red checklist.

    Answers "is Doberman actually wired up and healthy?" in one shot: host hooks,
    config, the decision DB, 2FA, the enforcement dial + strictness mode, and the
    fingerprint key. It only *diagnoses* - it never changes state. Exits non-zero
    if any critical check (hooks / config / DB) is not healthy, so it is
    script-friendly (`doberman doctor && ...`).
    """
    from doberman.cli.doctor import CheckStatus, critical_failures, run_checks

    # ASCII marks only: CLI output must survive a cp1252 console (see setup wizard).
    marks = {CheckStatus.OK: "[ ok ]", CheckStatus.WARN: "[warn]", CheckStatus.FAIL: "[FAIL]"}

    results = run_checks(path)
    failures = critical_failures(results)
    if as_json:
        payload = {
            "version": 1,
            "path": path,
            "ok": not failures,
            "checks": [
                {
                    "name": r.name,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "detail": r.detail,
                }
                for r in results
            ],
            "critical_failures": [f.name for f in failures],
        }
        typer.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        if failures:
            raise typer.Exit(code=1)
        return

    typer.echo("Doberman doctor")
    typer.echo("=" * 32)
    for result in results:
        typer.echo(f"{marks[result.status]} {result.name}: {result.detail}")

    typer.echo("")
    if failures:
        typer.echo(
            f"error: {len(failures)} critical check(s) not healthy - "
            "Doberman may not be protecting you."
        )
        raise typer.Exit(code=1)
    typer.echo("All critical checks passed.")


@hook_app.command("pre")
def hook_pre() -> None:
    """Claude Code PreToolUse hook - gate one tool call (allow / ask / deny).

    Reads the harness hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS - Doberman is raise-only and never
    suppresses the harness's own prompts). Runs only the fast deterministic
    objective floor (no numpy/scipy/river), so it adds minimal latency to every
    tool call, and fails closed (deny) on any malformed input or engine error.

    Wire it into Claude Code's settings (or run ``doberman install-hooks``).
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

    Wire it into Claude Code's settings (or run ``doberman install-hooks``).
    """
    _configure_stderr_logging()
    from doberman.hosthooks.claude_code import run_post_hook

    out = run_post_hook(sys.stdin.read())
    if out is not None:
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("openclaw")
def hook_openclaw() -> None:
    """OpenClaw ``before_tool_call`` plugin hook - gate one tool call.

    Reads the event as JSON on stdin (see ``adapters/openclaw/``) and ALWAYS
    writes exactly one JSON verdict to stdout - unlike the Claude Code hooks
    above, this bridge is a fresh subprocess spawned per call under a hard
    timeout on the OpenClaw side, so silence would be indistinguishable from a
    hang and the shim would fail closed on every benign PASS too.

    Runs only the fast deterministic objective floor (no numpy/scipy/river),
    fails closed (``{"verdict":"block",...}``) on any malformed input or
    engine error.

    Wire it into an OpenClaw gateway via the ``adapters/openclaw/`` plugin
    (see its README for install + the mandatory "verify it's live" canary).
    """
    _configure_stderr_logging()
    # Imported here, not at module scope, so the other CLI commands don't load
    # the decision path on every `--help`/`status`/`log` invocation.
    from doberman.hosthooks.openclaw import run_before_tool_call_hook

    out = run_before_tool_call_hook(sys.stdin.read())
    sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@hook_app.command("codex-pre")
def hook_codex_pre() -> None:
    """Codex CLI PreToolUse hook - gate one tool call (allow / ask / deny).

    Reads the Codex hook payload as JSON on stdin and writes the hook decision
    as JSON to stdout (nothing on a PASS - Doberman is raise-only). Codex's hook
    layer is a Claude Code compatibility shim, so this shares the same decision
    spine and deny shape as ``hook pre``; it runs only the fast deterministic
    objective floor (no numpy/scipy/river) and fails closed on any malformed
    input or engine error.

    Wire it in with ``doberman install-hooks --host codex`` (a later slice).
    """
    _configure_stderr_logging()
    from doberman.hosthooks.codex import run_codex_pre

    out = run_codex_pre(sys.stdin.read())
    if out is not None:
        sys.stdout.write(out + "\n")
    raise typer.Exit(0)


@password_app.command("set")
def password_set(
    force: bool = typer.Option(
        False, "--force", help="Rotate an existing password after proving the current one."
    ),
) -> None:
    """Set or deliberately rotate the local password possession factor."""
    prompter = CliPrompter()
    current_password = None
    if force and password.is_enrolled():
        current_password = prompter.read_code("Enter your current Doberman password")
    new_password = prompter.read_code("Enter a new Doberman password")
    repeated_password = prompter.read_code("Enter the new Doberman password again")
    if new_password != repeated_password:
        typer.echo("error: passwords do not match", err=True)
        raise typer.Exit(code=1)
    try:
        password.enroll(
            new_password,
            force=force,
            current_password=current_password,
        )
    except (ValueError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("Password set. Stored locally with owner-only permissions; never committed.")


@twofa_app.command("setup")
def twofa_setup(
    force: bool = typer.Option(
        False, "--force", help="Rotate an existing secret (invalidates the old one)."
    ),
) -> None:
    """Enroll TOTP two-factor and print the provisioning URI for your authenticator."""
    current_code = None
    if force and totp.is_enrolled():
        current_code = CliPrompter().read_code("Current 2FA code")
    try:
        uri = totp.enroll(force=force, current_code=current_code)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("2FA enrolled. Add this to your authenticator app (or scan it as a QR):")
    typer.echo(uri)
    typer.echo("This secret is stored locally with owner-only permissions and is never committed.")


@twofa_app.command("remove")
def twofa_remove() -> None:
    """Remove TOTP enrollment, proving possession of the factor being dropped.

    Losing a possession factor weakens Doberman, so this needs your current 2FA
    code — the same rate-limited check that gates a rotation. Removal is
    deliberately not delegable to the password: whoever drops 2FA must hold it.
    """
    if not totp.is_enrolled():
        typer.echo("error: 2FA is not enrolled; nothing to remove", err=True)
        raise typer.Exit(code=1)
    prompter = CliPrompter()
    if not prompter.confirm(
        "Remove 2FA? Policy weakenings will then be gated by your local password instead"
    ):
        typer.echo("error: aborted; 2FA is unchanged", err=True)
        raise typer.Exit(code=1)
    current_code = prompter.read_code("Current 2FA code")
    try:
        totp.unenroll(current_code=current_code)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("2FA removed. Delete the Doberman entry in your authenticator app too.")
    if not password.is_enrolled():
        typer.echo(
            "warning: no possession factor is enrolled now, so every policy weakening "
            "will be denied - run `doberman password set` (or `doberman 2fa setup`) to "
            "restore one.",
            err=True,
        )


@twofa_app.command("reset-lockout")
def twofa_reset_lockout() -> None:
    """Clear the TOTP lockout early, proving possession with your password.

    Too many wrong 2FA codes lock further attempts for a short cooldown. That
    window self-recovers, so this is a convenience: prove you own this machine
    and retry now instead of waiting. It is gated on your password, not 2FA - a
    locked-out factor cannot verify itself, and someone who tripped the lockout
    by guessing codes must not be able to lift it. Clearing the counter never
    disables the rate limiter: fresh wrong codes lock it again.
    """
    if not totp.is_enrolled():
        typer.echo("error: 2FA is not enrolled; there is no lockout to reset", err=True)
        raise typer.Exit(code=1)
    if not password.is_enrolled():
        typer.echo(
            "error: clearing the 2FA lockout needs your local password, but none is "
            "enrolled. The lockout clears itself after a short cooldown - wait it out, "
            "or run `doberman password set` to enable an early reset next time.",
            err=True,
        )
        raise typer.Exit(code=1)
    current_password = CliPrompter().read_code("Doberman password")
    if not password.verify(current_password):
        typer.echo("error: incorrect password; the 2FA lockout is unchanged", err=True)
        raise typer.Exit(code=1)
    totp.reset_attempts()
    typer.echo("2FA lockout cleared. You can enter a fresh code now.")


@taint_app.command("clear")
def taint_clear(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Clear this repo's sticky session taint — a gated recovery action.

    Reading a secret taints a session for the rest of it (by design — a timed
    reset would just be a bypass an attacker waits out), and in strict/paranoid
    that raises every later egress to AUTH or BLOCK. This is the explicit,
    human-only escape hatch: it requires an enrolled possession factor (2FA if
    set up, otherwise your Doberman password) and clears BOTH taint stores for
    this repo. There is no confirm-only path and no silent timer.
    """
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: clearing taint requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        approved, method = _verify_possession_factor(prompter, action_label="clearing taint")
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the clear
        # `_verify_possession_factor` does not guard its own prompt; its other
        # caller (`_run_weaken_gate`) wraps it for exactly this reason. A
        # non-interactive stdin raises rather than returning, and an unguarded
        # raise here would be a traceback, not a denial.
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: taint clear denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        taint_rows, fingerprint_rows = asyncio.run(clear_taint(path))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed clear
        typer.echo(f"error: taint clear failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        f"Taint cleared ({taint_rows} record(s), {fingerprint_rows} fingerprint(s)). "
        "This session's memory of a secret being read is gone; egress in this repo "
        "returns to the mode default until something taints it again."
    )


@tools_app.command("approve")
def tools_approve(
    tool_name: str = typer.Argument(..., help="Tool name whose last-seen schema to approve."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Approve a changed MCP tool fingerprint after possession-factor verification."""
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: approving a tool pin requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    try:
        approved, method = _verify_possession_factor(
            CliPrompter(), action_label=f"approving the {tool_name} tool pin"
        )
    except Exception:  # noqa: BLE001 - any input/EOF/timeout error denies approval
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: tool pin approval denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        approved_fp = asyncio.run(approve_pin(tool_name, repo_root=path))
    except Exception as exc:  # noqa: BLE001 - failed storage update is never success
        typer.echo(f"error: tool pin approval failed (error class: {type(exc).__name__})", err=True)
        raise typer.Exit(code=1) from exc
    if approved_fp is None:
        typer.echo(f"error: no last-seen pin exists for tool {tool_name}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Tool pin approved for {tool_name}: {approved_fp}")


@app.command(rich_help_panel="Auth")
def revoke(
    elevation_id: str = typer.Argument(..., help="Id of the elevation to revoke."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Revoke an active role elevation by id (see `doberman status`)."""
    revoked = asyncio.run(revoke_elevation(path, elevation_id))
    if revoked:
        typer.echo(f"revoked elevation {elevation_id}")
    else:
        typer.echo(f"error: no elevation with id {elevation_id}", err=True)
        raise typer.Exit(code=1)


@app.command(rich_help_panel="Daily")
def tune(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    json_out: bool = typer.Option(
        False, "--json", help="Emit the report + proposals as one JSON document."
    ),
    last: int = typer.Option(2000, "--last", help="Consider the most recent N decisions."),
    min_occurrences: int = typer.Option(
        5,
        "--min-occurrences",
        help="Minimum all-approved occurrences before a standing-elevation proposal is emitted.",
    ),
    accept: str = typer.Option(
        None, "--accept", help="Accept a proposal id from the last `doberman tune` report."
    ),
) -> None:
    """Friction report - interventions/session, top AUTH reasons - plus gated tuning proposals.

    Never applies anything by itself. Where an AUTH class has been approved
    every time, often enough, `doberman tune` proposes a standing, revocable,
    time-limited elevation; `--accept <id>` routes acceptance through the same
    possession-factor-gated weaken chokepoint as any other policy loosening
    (`doberman revoke <elevation-id>` reverses it early).
    """
    rows = asyncio.run(read_decisions(path, limit=max(0, last)))
    proposals = generate_proposals(rows, min_occurrences=min_occurrences)

    if accept is not None:
        proposal = next((p for p in proposals if p["id"] == accept), None)
        if proposal is None:
            typer.echo("error: unknown or stale proposal id; rerun 'doberman tune'", err=True)
            raise typer.Exit(code=1)
        typer.echo(proposal["what_would_loosen"])
        outcome = asyncio.run(
            apply_standing_elevation(
                scope_glob=proposal["target_path_class"],
                reason=f"doberman tune accept {accept}",
                repo_root=path,
                ttl_days=proposal["ttl_days"],
            )
        )
        if not outcome.approved:
            typer.echo("error: change denied; nothing granted", err=True)
            raise typer.Exit(code=1)
        grant = asyncio.run(
            grant_elevation(
                path,
                proposal["target_path_class"],
                task_id=f"tune:{accept}",
                now=datetime.now(timezone.utc),
                ttl_seconds=proposal["ttl_days"] * 86400,
            )
        )
        typer.echo(
            f"Granted standing elevation {grant.id} for {proposal['target_path_class']} "
            f"until {grant.expires_at.isoformat()}. Revoke any time: doberman revoke {grant.id}"
        )
        return

    report = build_friction_report(rows)
    if json_out:
        typer.echo(json.dumps({**report, "proposals": proposals}, sort_keys=True, default=str))
        return

    if not rows:
        typer.echo("(no decisions recorded yet)")
        return

    typer.echo("Doberman friction report")
    typer.echo("=" * 32)
    ips = report["interventions_per_session"]
    typer.echo(
        f"Interventions/session: {ips:.2f}" if ips is not None else "Interventions/session: n/a"
    )
    typer.echo(
        f"{report['decisions']} decisions across {report['sessions']} session(s) "
        f"({report['unsessioned_decisions']} unsessioned); {report['interventions']} intervention(s) (AUTH)"
    )
    if report["top_auth_reason_codes"]:
        typer.echo("Top AUTH reasons:")
        for code, n in report["top_auth_reason_codes"]:
            typer.echo(f"  {code}: {n}")
    if report["approval_rate_by_reason"]:
        typer.echo("Approval rate by reason:")
        for code, stats in sorted(report["approval_rate_by_reason"].items()):
            rate = f"{stats['rate']:.0%}" if stats["rate"] is not None else "n/a"
            typer.echo(f"  {code}: {stats['approved']}/{stats['n']} ({rate})")
    if report["approval_rate_by_target"]:
        typer.echo("Approval rate by target:")
        for target, stats in sorted(report["approval_rate_by_target"].items()):
            rate = f"{stats['rate']:.0%}" if stats["rate"] is not None else "n/a"
            typer.echo(f"  {target}: {stats['approved']}/{stats['n']} ({rate})")
    if report["trend"]:
        typer.echo("Recent trend:")
        for week, stats in sorted(report["trend"].items())[-8:]:
            week_ips = stats["interventions_per_session"]
            week_ips_str = f"{week_ips:.2f}/session" if week_ips is not None else "n/a"
            typer.echo(
                f"  {week}: {stats['decisions']} decisions, {stats['interventions']} interventions, "
                f"{stats['sessions']} session(s), {week_ips_str}"
            )
    if proposals:
        typer.echo("")
        typer.echo("Tuning proposals (nothing applied automatically):")
        for p in proposals:
            typer.echo(f"  [{p['id']}] {p['what_would_loosen']}")
            typer.echo(f"    why: {p['why']}")
            typer.echo(f"    To accept: doberman tune --accept {p['id']}")
        typer.echo(
            "  Accepting requires your possession factor and grants a revocable, "
            "time-limited elevation (doberman revoke <elevation-id>)."
        )


# Columns from ``_DECISION_COLUMNS`` that ``log --jsonl`` emits in addition to the
# six fields the human view shows. Every one is already redacted at write time by
# ``build_record`` — no raw target, argument, or secret reaches the table at all.
_JSONL_EXTRA_COLUMNS = ("id", "agent_role", "risk")


@app.command(rich_help_panel="Daily")
def log(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N decisions."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    jsonl: bool = typer.Option(
        False,
        "--jsonl",
        help="Emit one redacted JSON object per line (no headings; empty if none).",
    ),
) -> None:
    """Show the recent redacted decision log (newest first).

    Every row is already redacted - a path class, reason codes, the verdict, and
    the auth outcome. No raw target, argument, or secret is ever stored or shown.
    """
    rows = asyncio.run(read_decisions(path, limit=max(0, last)))
    if jsonl:
        for row in rows:
            # Decode structured fields; keep only the redacted representation.
            try:
                reasons = json.loads(row.get("reason_codes_json") or "[]")
            except json.JSONDecodeError:
                reasons = []
            if not isinstance(reasons, list):
                reasons = []
            record = {
                "ts": row.get("ts"),
                "final_verdict": row.get("final_verdict"),
                "action_type": row.get("action_type"),
                "target_path_class": row.get("target_path_class"),
                "reason_codes": reasons,
                "auth_result": row.get("auth_result"),
            }
            # Include other redacted columns if present. This is an allowlist on
            # purpose: a column added to the decisions table later must be opted
            # in here deliberately, rather than leaking into the stream by default.
            record.update({key: row[key] for key in _JSONL_EXTRA_COLUMNS if key in row})
            typer.echo(json.dumps(record, sort_keys=True, separators=(",", ":"), default=str))
        return
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
            f"{row['ts']}  {verdict_label_str(row['final_verdict'])} {row['action_type']:<13} "
            f"{target}  [{reasons}]{auth}"
        )


@app.command(rich_help_panel="Daily")
def tui(
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Browse the redacted decision log interactively, with a plain-language "why" panel.

    Every row shown is already redacted - a path class, reason codes, the verdict,
    and the auth outcome - the same data `doberman log` prints. Requires the
    optional 'textual' extra; `doberman log` remains the plain, dependency-free
    fallback.
    """
    if importlib.util.find_spec("textual") is None:
        typer.echo(
            "error: The TUI requires the optional 'textual' extra: "
            'pip install "doberman-core[tui]"',
            err=True,
        )
        raise typer.Exit(code=1)
    from doberman.tui import run_tui

    run_tui(path)


_DASH_HOST = "127.0.0.1"
_DASH_DEFAULT_PORT = 8642


@app.command(rich_help_panel="Daily")
def dash(
    port: int = typer.Option(_DASH_DEFAULT_PORT, "--port", help="Port to bind the dashboard to."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root to report on."),
) -> None:
    """Launch the local dashboard (preview) - a localhost-only control surface.

    Binds to 127.0.0.1 only, never a public interface. A fresh, single-use
    token is generated for this run and embedded in the printed URL; every API
    route requires it as a bearer token, checked in constant time. Reports the
    live decision feed, summary stats, mode, and enforcement state for
    ``--path`` (default: the current repo), plus an interactive AUTH
    approve/deny queue: a challenge on the decision path engages this
    dashboard only while it is running (see the heartbeat below), and falls
    back to the terminal/GUI otherwise. Requires the optional 'dash' extra.
    """
    try:
        import uvicorn

        from doberman.dash import create_app
    except ImportError as exc:
        typer.echo(
            'error: The dashboard requires the optional "dash" extra: '
            'pip install "doberman-core[dash]"',
            err=True,
        )
        raise typer.Exit(code=1) from exc

    import threading

    from doberman.storage.heartbeat import touch_heartbeat

    # ponytail: a daemon thread ticking a file mtime - simplest possible
    # liveness signal the decision-path process can check without any IPC.
    # Dies with the process; no explicit stop needed for a CLI-lifetime thread.
    stop_heartbeat = threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.is_set():
            touch_heartbeat(path)
            stop_heartbeat.wait(2.0)

    threading.Thread(target=_heartbeat_loop, daemon=True).start()

    token = secrets.token_urlsafe(32)
    typer.echo(f"Dashboard: http://{_DASH_HOST}:{port}/?token={token}")
    # access_log=False: the single-use token rides in the URL query string, so
    # uvicorn's request access log would write it verbatim into a log line.
    # Disable it so the bearer token never lands in a log.
    uvicorn.run(create_app(token, path), host=_DASH_HOST, port=port, access_log=False)


@app.command(rich_help_panel="Daily")
def demo(
    path: str = typer.Option(".", "--path", "-p", help="Repository root to log decisions against."),
    mode: str = typer.Option(
        "balanced", "--mode", help="Security mode to evaluate scenarios under."
    ),
    fast: bool = typer.Option(False, "--fast", help="Skip the pacing delay between scenarios."),
) -> None:
    """Run a scripted attack reel through the REAL decision engine.

    Drives a fixed list of canned tool calls -- a secret-exfiltration attempt,
    a destructive command, a protected-branch force push, a Unicode-smuggled
    egress, a sensitive-file read, a git clone to an external host (the real
    engine's AUTH verdict -- human-in-the-loop, not a fake one), and two
    benign calls -- through the SAME normalize -> decide -> record_decision
    pipeline the real proxy uses, so the redacted decision log (and
    `doberman dash`) fills with genuine verdicts. Nothing is ever executed
    against a real tool or downstream server: no network call, no unexpected
    file mutation, and no auth prompt (an AUTH verdict is recorded and shown
    here, never challenged).
    """
    try:
        resolved_mode = resolve_mode(mode)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("Doberman demo -- scripted attack reel (real engine, nothing executed)")
    typer.echo("")

    outcomes = run_demo(
        mode=resolved_mode.value,
        repo_root=path,
        fast=fast,
        on_scenario=lambda outcome: typer.echo(format_outcome_line(outcome)),
    )

    typer.echo("")
    typer.echo(format_summary_table(outcomes))
    typer.echo("")
    typer.echo("Run `doberman dash` in another terminal to watch this live.")

    if not all(outcome.matched for outcome in outcomes):
        raise typer.Exit(code=1)


@memory_app.callback(invoke_without_command=True, rich_help_panel="Policy")
def memory(
    ctx: typer.Context,
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Show a plain-language, redaction-safe profile of what Doberman has learned.

    Reads as classifications and habits - counts, verdict mix, most-touched path
    classes, and how many distinct secrets have been *seen* (a count only). It
    never shows a fingerprint value or any raw secret.

    Run with no subcommand for this summary; see `doberman memory reset` (gated
    wipe of the learned behavioral baseline/preference memory) and `doberman
    memory prune` (drop stale entities' rows past a retention window).
    """
    if ctx.invoked_subcommand is not None:
        return
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


@memory_app.command("reset")
def memory_reset(
    entity: str | None = typer.Option(
        None, "--entity", help="Scope to one entity id; omit to reset every entity in this repo."
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Wipe learned behavioral memory for this repo — a gated recovery action.

    The subjective baseline and revealed-preference tables are persistent,
    per-entity memory (RAND's "reliable deletion" requirement): if that memory
    were ever poisoned — trained on a compromised session's behavior — nothing
    short of this clears it. Deleting it is raise-SAFE by construction (same as
    the v2->v3 baseline re-key): a colder baseline scores everything as MORE
    novel until it relearns, never less protected. Requires an enrolled
    possession factor (2FA if set up, otherwise your Doberman password), the
    same gate as `doberman taint clear` - there is no confirm-only path. A
    successful reset is recorded to the append-only policy-change ledger
    (`doberman policy-history`), redacted to a row count and an entity-scope
    class - never raw baseline content. A denied attempt leaves no ledger row,
    same as `doberman taint clear` (ADR 0067).
    """
    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "error: resetting memory requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        approved, method = _verify_possession_factor(
            prompter, action_label="resetting learned memory"
        )
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the reset
        # Mirrors taint_clear: `_verify_possession_factor` does not guard its own
        # prompt, so a non-interactive stdin must deny cleanly, not traceback.
        approved, method = False, "denied"

    scope_label = "one entity" if entity else "all entities"
    if not approved:
        # No ledger row here: `apply_change` can only record what it itself
        # decided (a same-state before/after always classifies neutral ->
        # auto-approved), so forcing a denied attempt through it would
        # misrecord the denial as approved. Mirrors `doberman taint clear`,
        # which also leaves a denied gate with no ledger trace (ADR 0067).
        typer.echo(f"error: memory reset denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    try:
        counts = asyncio.run(reset_memory(path, entity))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed reset
        typer.echo(f"error: memory reset failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    total = sum(counts.values())
    asyncio.run(
        apply_change(
            {"memory.reset": "present"},
            {"memory.reset": f"cleared:{scope_label}"},
            f"doberman memory reset ({scope_label}, {total} row(s))",
            repo_root=path,
        )
    )
    typer.echo(
        f"Memory reset ({scope_label}, {total} row(s) across {len(counts)} table(s)). "
        "The learned baseline/preference history for this scope is gone; it starts "
        "cold and relearns from here - colder means more novel, never less protected."
    )


@memory_app.command("prune")
def memory_prune(
    older_than_days: int = typer.Option(
        ...,
        "--older-than-days",
        min=1,
        help="Drop every entity whose most recent activity is older than this many days.",
    ),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
) -> None:
    """Drop stale entities' learned memory past a retention window.

    A maintenance op, not a security decision - unlike `doberman memory reset`
    this is not gated behind a possession factor. It never touches the decision
    log (the audit trail is not behavioral memory) and never prunes an entity
    whose activity can't be dated (fail-safe: unknown age is never treated as
    stale). Output is counts only - entity ids are never printed.
    """
    try:
        result = asyncio.run(prune_stale_entities(path, older_than_days=older_than_days))
    except Exception as exc:  # noqa: BLE001 — never report success on a failed prune
        typer.echo(f"error: memory prune failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    entities = result.pop("entities_pruned")
    total_rows = sum(result.values())
    typer.echo(
        f"Memory pruned: {entities} stale entity class(es), {total_rows} row(s) across "
        f"{len(result)} table(s) untouched for {older_than_days}+ day(s)."
    )


@app.command("policy-history", rich_help_panel="Policy")
def policy_history(
    last: int = typer.Option(20, "--last", "-n", help="Show the most recent N changes."),
    path: str = typer.Option(".", "--path", "-p", help="Repository root."),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print redacted ledger rows as a JSON array (machine-readable).",
    ),
) -> None:
    """Show the append-only policy-change ledger (newest first).

    Records every classified change - strengthen / weaken / neutral - **including
    denied weakening attempts** (the poisoning signal). Each row shows the rule,
    the before->after states, the classification, and how it was approved.
    """
    rows = asyncio.run(read_policy_changes(path, limit=max(0, last)))
    if as_json:
        # Same redacted row dicts the human view uses (no raw paths/secrets).
        typer.echo(json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str))
        return
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


@app.command("install-hooks", rich_help_panel="Getting started")
def install_hooks(
    global_: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Install into the user-wide file (Claude: ~/.claude; Codex: ~/.codex).",
    ),
    local: bool = typer.Option(
        False, "--local", help="Install into .claude/settings.local.json (Claude only)."
    ),
    host: str = typer.Option("claude", "--host", help="Which host to wire: claude | codex."),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Wire Doberman's hooks into a host so every tool call is gated before it runs.

    Idempotent - safe to run more than once. Claude Code (default): PreToolUse +
    PostToolUse + SessionStart into a ``settings.json`` (``--global`` user-wide,
    ``--local`` project-local, else project ``.claude/settings.json``). Codex CLI
    (``--host codex``): a PreToolUse hook into a ``hooks.json`` (``--global`` ->
    ``~/.codex/hooks.json``, else ``<repo>/.codex/hooks.json``).
    """
    if host == "codex":
        _install_codex(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host != "claude":
        typer.echo(f"error: unknown --host {host!r}; expected 'claude' or 'codex'.", err=True)
        raise typer.Exit(2)

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
    if remove_exclusion(path):
        typer.echo("This project is no longer excluded from global hooks.")


def _install_codex(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`install-hooks --host codex`: wire ``doberman hook codex-pre`` into a
    Codex hooks.json. ``--global`` -> ``~/.codex/hooks.json`` (user), else
    ``<repo>/.codex/hooks.json`` (repo). ``--local`` has no Codex equivalent."""
    if local:
        typer.echo(
            "error: --local has no Codex equivalent; use --global (user) or the default (repo).",
            err=True,
        )
        raise typer.Exit(2)
    from doberman.hosthooks.install import load_settings, write_settings
    from doberman.hosthooks.install_codex import merge_codex_hooks, resolve_codex_hooks_path

    scope = "user" if global_ else "repo"
    hooks_path = resolve_codex_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    merged = merge_codex_hooks(current)

    if dry_run:
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would add:")
        typer.echo("  PreToolUse -> doberman hook codex-pre")
        return

    write_settings(hooks_path, merged)
    typer.echo(f"wrote {hooks_path}")
    typer.echo("Doberman will now gate Codex's tool calls in this scope.")
    if remove_exclusion(path):
        typer.echo("This project is no longer excluded from global hooks.")
    typer.echo("")
    typer.echo("Codex requires you to TRUST this hook before it runs:")
    typer.echo("  run a Codex command and approve the hook when prompted, or launch with")
    typer.echo("  --dangerously-bypass-hook-trust only if you already vet the hook source.")
    typer.echo("Verify it's live: ask Codex to `cat .env` and confirm it is blocked.")


def _uninstall_codex(*, global_: bool, local: bool, path: str, dry_run: bool) -> None:
    """`uninstall-hooks --host codex`: remove Doberman's Codex hook group."""
    if local:
        typer.echo("error: --local has no Codex equivalent.", err=True)
        raise typer.Exit(2)
    from doberman.hosthooks.install import _is_doberman_group, load_settings, write_settings
    from doberman.hosthooks.install_codex import remove_codex_hooks, resolve_codex_hooks_path

    scope = "user" if global_ else "repo"
    hooks_path = resolve_codex_hooks_path(scope, path)

    try:
        current = load_settings(hooks_path)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    hooks_section = current.get("hooks") or {}
    had_doberman = any(
        _is_doberman_group(g)
        for groups in hooks_section.values()
        if isinstance(groups, list)
        for g in groups
    )
    if not had_doberman:
        typer.echo("No Doberman Codex hooks found - nothing to remove.")
        return

    cleaned = remove_codex_hooks(current)
    if dry_run:
        typer.echo(f"[dry-run] target: {hooks_path}")
        typer.echo("[dry-run] would remove:  PreToolUse -> doberman hook codex-pre")
        return

    write_settings(hooks_path, cleaned)
    typer.echo(f"wrote {hooks_path}")
    typer.echo("Doberman Codex hooks removed.")
    typer.echo(
        "Note: a plugin-bundled hook (if installed) is removed by removing the plugin "
        "(`codex plugin remove`), not by this command."
    )


@app.command("uninstall-hooks", rich_help_panel="Getting started")
def uninstall_hooks(
    global_: bool = typer.Option(
        False,
        "--global",
        "-g",
        help="Remove from the user-wide file (Claude: ~/.claude; Codex: ~/.codex).",
    ),
    local: bool = typer.Option(
        False, "--local", help="Remove from .claude/settings.local.json (Claude only)."
    ),
    host: str = typer.Option("claude", "--host", help="Which host to unwire: claude | codex."),
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would change; write nothing."
    ),
) -> None:
    """Remove Doberman's hooks from a host.

    Idempotent - safe to run even when hooks are not present.  Non-Doberman hooks
    and every other setting are left untouched. ``--host codex`` removes the Codex
    hook group instead of the Claude Code hooks.
    """
    if host == "codex":
        _uninstall_codex(global_=global_, local=local, path=path, dry_run=dry_run)
        return
    if host != "claude":
        typer.echo(f"error: unknown --host {host!r}; expected 'claude' or 'codex'.", err=True)
        raise typer.Exit(2)

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
    typer.echo("")
    typer.echo("What remains (manual, optional cleanup):")
    typer.echo("  .doberman/              policy, decision log, taint state")
    typer.echo("  ~/.doberman/metrics.db  device metrics")
    typer.echo("  password / 2FA enrollment")
    typer.echo(
        "These are not removed automatically; delete them only if you no longer use Doberman."
    )
    typer.echo("Run `doberman uninstall` to also remove this project's `.doberman/` state.")


def _project_uninstall_targets(path: str) -> list[tuple[str, str]]:
    """Project-scoped removal targets: ``(description, path)`` pairs.

    Deliberately excludes the ``global``/``user`` hook scopes (they protect every
    project on this machine, not just this one) and the Codex ``plugin`` scope
    (owned by ``codex plugin``, not writable here) — ``doberman uninstall`` is
    project-scoped only.
    """
    from doberman.hosthooks.install_codex import codex_hook_install_states

    targets: list[tuple[str, str]] = []
    for scope, settings_path, installed in _hook_install_states(path):
        if scope in ("project", "local") and installed:
            targets.append((f"Claude Code hooks ({scope})", settings_path))
    for scope, hooks_path, installed in codex_hook_install_states(path):
        if scope == "repo" and installed:
            targets.append(("Codex CLI hooks (repo)", hooks_path))
    doberman_dir = Path(path) / CONFIG_DIR
    if doberman_dir.exists():
        targets.append((".doberman/ (policy + decision database)", str(doberman_dir)))
    return targets


@app.command(rich_help_panel="Getting started")
def uninstall(
    path: str = typer.Option(".", "--path", "-p", help="Project root (default: current dir)."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the typed confirmation. The possession-factor check is never skipped.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would be removed; remove nothing."
    ),
) -> None:
    """Fully remove Doberman from this project: host hooks + `.doberman/`.

    Project-scoped only. This does **not** touch `--global` hooks themselves (they
    protect every project on this machine) or your device-wide password / 2FA /
    fingerprint key / `~/.doberman/metrics.db` — removing those is a separate,
    deliberate action, not a side effect of cleaning up one project. But a global
    (or Codex user-scope) hook would otherwise keep firing here even after this
    project's own hooks/`.doberman/` are gone, so when one is detected as still
    installed, this project is also added to a device-wide exclusion list that the
    global hook checks and skips — closing that gap without touching the hook file
    itself. Run `doberman install-hooks` here again to clear the exclusion.

    Requires an enrolled possession factor (2FA if set up, otherwise your Doberman
    password) — the same gate as `doberman taint clear` / `doberman memory reset`.
    With neither enrolled, this fails closed and removes nothing. A destructive,
    irreversible action, so it also asks you to type the project directory name
    back before proceeding (skippable with `--yes`; the factor check is not).
    """
    from doberman.hosthooks.install_codex import (
        codex_hook_install_states,
        remove_codex_hooks,
        resolve_codex_hooks_path,
    )

    targets = _project_uninstall_targets(path)
    if not targets:
        typer.echo("Nothing to remove for this project.")
        return

    global_hook_active = any(
        scope == "global" and installed for scope, _, installed in _hook_install_states(path)
    ) or any(
        scope == "user" and installed for scope, _, installed in codex_hook_install_states(path)
    )

    project_name = Path(path).resolve().name
    typer.echo(f"Doberman UNINSTALL requested for this project ({Path(path).resolve()}):")
    for description, target_path in targets:
        typer.echo(f"  - {description}: {target_path}")
    typer.echo("")
    typer.echo("This will NOT remove (shared across every project on this machine):")
    typer.echo("  - hooks installed with --global")
    typer.echo("  - your Doberman password / 2FA enrollment / fingerprint key")
    typer.echo("  - ~/.doberman/metrics.db (device metrics)")
    if global_hook_active:
        typer.echo("")
        typer.echo(
            "A global (or Codex user-scope) hook is still installed on this machine — this "
            "project will also be added to the device-wide exclusion list, so it skips it too."
        )

    if dry_run:
        typer.echo("")
        typer.echo("[dry-run] nothing removed.")
        return

    if not totp.is_enrolled() and not password.is_enrolled():
        typer.echo(
            "\nerror: uninstalling requires an enrolled possession factor - "
            "run `doberman 2fa setup` or `doberman password set` first",
            err=True,
        )
        raise typer.Exit(code=1)

    prompter = CliPrompter()
    try:
        if not yes:
            if not prompter.confirm("\nProceed?"):
                typer.echo("error: uninstall denied (confirmation declined); unchanged", err=True)
                raise typer.Exit(code=1)
            typed = typer.prompt(f"Type the project directory name ({project_name}) to confirm")
            if typed.strip() != project_name:
                typer.echo("error: uninstall denied (name did not match); unchanged", err=True)
                raise typer.Exit(code=1)
        approved, method = _verify_possession_factor(
            prompter, action_label="uninstalling Doberman from this project"
        )
    except typer.Exit:
        raise
    except Exception:  # noqa: BLE001 — any input/EOF/timeout error denies the uninstall
        approved, method = False, "denied"
    if not approved:
        typer.echo(f"error: uninstall denied ({method}); unchanged", err=True)
        raise typer.Exit(code=1)

    from doberman.hosthooks.install import (
        load_settings,
        remove_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )

    errors: list[str] = []
    for scope, settings_path, installed in _hook_install_states(path):
        if scope not in ("project", "local") or not installed:
            continue
        try:
            current = load_settings(resolve_settings_path(scope, path))
            write_settings(resolve_settings_path(scope, path), remove_doberman_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{settings_path}: {exc}")

    for scope, hooks_path, installed in codex_hook_install_states(path):
        if scope != "repo" or not installed:
            continue
        try:
            current = load_settings(resolve_codex_hooks_path(scope, path))
            write_settings(resolve_codex_hooks_path(scope, path), remove_codex_hooks(current))
        except (ValueError, OSError) as exc:
            errors.append(f"{hooks_path}: {exc}")

    doberman_dir = Path(path) / CONFIG_DIR
    if doberman_dir.exists():
        try:
            shutil.rmtree(doberman_dir)
        except OSError as exc:
            errors.append(f"{doberman_dir}: {exc}")

    if errors:
        typer.echo("error: uninstall finished with errors - some items were NOT removed:", err=True)
        for err in errors:
            typer.echo(f"  - {err}", err=True)
        raise typer.Exit(code=1)

    typer.echo("\nDoberman removed from this project.")

    if global_hook_active:
        add_exclusion(path)
        typer.echo(
            "This project has been added to the device-wide exclusion list, so the global "
            "(or Codex user-scope) hook will skip it too. Run `doberman install-hooks` here "
            "to bring protection back."
        )


@app.command(rich_help_panel="Getting started")
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
    Later lowerings require a possession factor — a 2FA code if enrolled,
    otherwise your Doberman password (set via ``doberman password set``).
    Pass ``--yes`` for a fully non-interactive run (useful for CI or scripting).
    """
    from doberman.hosthooks.install import (
        load_settings,
        merge_doberman_hooks,
        resolve_settings_path,
        write_settings,
    )
    from doberman.hosthooks.setup import (
        DIMENSION_DESCRIPTIONS,
        mode_menu_lines,
        parse_mode_choice,
    )
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
        while True:
            raw = typer.prompt("Choose a mode (name or number)", default="balanced")
            try:
                chosen_mode = parse_mode_choice(raw)
                break
            except ValueError as exc:
                typer.echo(f"  {exc} - try again")

    # Save the chosen mode. First-run onboarding establishes the initial posture
    # freely (establish_ok); a re-run over an existing policy still gates a
    # lowering behind a possession factor, so setup can't bypass the mode gate.
    try:
        if (
            _apply_mode_change(chosen_mode.value, path, "doberman setup wizard", establish_ok=True)
            is None
        ):
            typer.echo(
                "note: mode not lowered (a lowering needs an enrolled possession factor); "
                "keeping the current mode",
                err=True,
            )
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
            typer.echo(f"  {DIMENSION_DESCRIPTIONS[dim]}")
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
    # d. Hook installation scope
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
    # e. Summary
    # ------------------------------------------------------------------
    typer.echo("")
    typer.echo("-- Setup complete ------------------------------------------")
    typer.echo(f"Mode:       {chosen_mode.value}")
    typer.echo(
        f"Prefs:      {'custom (tuned)' if tune_prefs else 'preset defaults for ' + chosen_mode.value}"
    )
    typer.echo(f"Hooks:      written to {settings_path}")
    typer.echo("")
    typer.echo("Doberman is now active.")
    typer.echo("Restart your Claude Code session to pick up the hooks.")
    typer.echo(
        "Next steps: `doberman password set`  |  `doberman 2fa setup` (optional)  |  "
        "`doberman status`  |  `doberman uninstall-hooks` (exit)"
    )


@app.command("session-summary")
def session_summary() -> None:
    """Print the device-global session-guard summary and exit.

    Formerly ``doberman dashboard``.

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


@app.command("dashboard", hidden=True)
def dashboard() -> None:
    """Run the deprecated alias for ``doberman session-summary``."""
    session_summary()


@app.command(rich_help_panel="Advanced")
def version() -> None:
    """Print the installed Doberman version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
