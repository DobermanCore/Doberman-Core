"""Render confirm-tier AUTH challenges inside the agent client via MCP elicitation.

The first channel in the serve-mode chain: when the agent client (Claude Code,
Codex, Cursor, …) declares the ``elicitation`` capability, Doberman sends an
``elicitation/create`` request over the live agent session and the client renders
the challenge natively in its own UI — the human answers right where they are
working, with no OS dialog and no terminal contention. Clients route elicitation
to the *user*, not the model, so the agent cannot approve its own action.

Two hard rules shape this module:

* **No sensitive data.** The MCP spec forbids requesting sensitive information
  via elicitation, so :meth:`ElicitationPrompter.read_code` always raises
  :class:`~doberman.auth.gui_prompter.PrompterUnavailableError` — one-time codes
  stay on the out-of-band channels (GUI dialog / terminal). The approval itself
  requests **zero** form fields: the accept/decline buttons are the answer, so
  nothing transits the client.
* **Never block the event loop.** The challenge answer arrives over the same MCP
  session this server runs on; waiting for it on the loop thread would deadlock.
  The executor runs challenges in a worker thread and this prompter bridges back
  with ``run_coroutine_threadsafe`` — and refuses (channel-unavailable) if it
  ever finds itself on the loop thread.

Failure taxonomy: missing capability / no active request / method-not-found →
``PrompterUnavailableError`` (the chain falls through to the GUI). A human
``decline``/``cancel`` is a FINAL denial, a timeout raises (deny), and any other
protocol error propagates (deny). Silence never approves.
"""

import asyncio
import concurrent.futures
import logging
from typing import Any

from mcp import types
from mcp.shared.exceptions import McpError
from mcp.types import METHOD_NOT_FOUND

from doberman.auth.gui_prompter import PrompterUnavailableError

logger = logging.getLogger("doberman.auth.elicitation")

#: Approval is expressed through the client's accept/decline buttons alone — no
#: form fields are requested, so no data (sensitive or otherwise) transits the client.
_APPROVAL_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

#: How long to wait for the human's answer. Sized for a person, not a protocol RTT;
#: on expiry the challenge denies (module-level so tests can shrink it).
ANSWER_TIMEOUT_S = 300.0


class ElicitationPrompter:
    """Collect a confirm through the agent client's native elicitation UI.

    Holds the proxy ``Server`` (to resolve the per-request session) and the serve
    event loop (to schedule the request from the challenge worker thread). Only
    ``confirm`` is offered on this channel — see the module docstring.
    """

    def __init__(self, server: Any, loop: asyncio.AbstractEventLoop) -> None:
        self._server = server
        self._loop = loop

    def confirm(self, message: str) -> bool:
        """Ask the human via the client UI. Only an explicit ``accept`` approves.

        ``decline`` and ``cancel`` (dismissed without choosing) both deny — and the
        denial is final: this raises nothing, so a fallback chain never re-asks.
        """
        return self._elicit_action(message) == "accept"

    def read_code(self, message: str) -> str:
        """One-time codes never transit the agent client — always unavailable."""
        raise PrompterUnavailableError(
            "one-time codes are sensitive and never requested via MCP elicitation; "
            "use the out-of-band channel"
        )

    def _elicit_action(self, message: str) -> str:
        """Send the elicitation and block (off-loop) for the human's action."""
        self._refuse_loop_thread()
        session = self._active_session()
        if not self._supports_elicitation(session):
            raise PrompterUnavailableError("agent client does not support MCP elicitation")

        future = asyncio.run_coroutine_threadsafe(
            session.elicit_form(message, requestedSchema=_APPROVAL_SCHEMA), self._loop
        )
        try:
            result = future.result(timeout=ANSWER_TIMEOUT_S)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()  # best-effort: withdraw the stale request
            raise EOFError("no elicitation answer from the agent client") from exc
        except McpError as exc:
            if exc.error.code == METHOD_NOT_FOUND:
                # The client advertised the capability but cannot serve it.
                raise PrompterUnavailableError(
                    "agent client rejected the elicitation request"
                ) from exc
            raise  # any other protocol failure → the provider denies
        return result.action

    def _refuse_loop_thread(self) -> None:
        """Refuse to block the loop that must carry the answer (it would deadlock)."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            return  # a worker thread — exactly where we want to be
        if running is self._loop:
            logger.warning("elicitation prompter invoked on the event-loop thread; refusing")
            raise PrompterUnavailableError("elicitation cannot run on the serve event-loop thread")

    def _active_session(self) -> Any:
        """The agent session of the request being decided. Unavailable outside one."""
        try:
            return self._server.request_context.session
        except LookupError as exc:
            raise PrompterUnavailableError("no active MCP request context") from exc

    @staticmethod
    def _supports_elicitation(session: Any) -> bool:
        """True when the client declared the elicitation capability (else fall through)."""
        try:
            return bool(
                session.check_client_capability(
                    types.ClientCapabilities(elicitation=types.ElicitationCapability())
                )
            )
        except Exception:  # malformed capability state — treat as unsupported
            logger.warning("could not determine client elicitation capability; skipping")
            return False
