"""Regenerate the OrcaRouter dashboard evidence under ``orca-evidence/``.

Starts the project's real Starlette dashboard on a free loopback port, drives
it with headless Chromium through Playwright, and writes ``manifest.json`` plus
the three screenshots into ``orca-evidence/`` at the repository root. Exits
non-zero if any assertion fails.

The evidence directory is generated output, never committed: it is produced by
``tests/integration/test_orcarouter_evidence.py`` (which is how CI and the
release validator run it) or by running this file directly.

The page is the shipped shell (``doberman.dash``), not a fixture: the model
list it shows is whatever ``GET /v1/models`` on the pinned origin returned for
this run. Nothing here fabricates a catalog entry or a model option.

Credentials: if ``ORCAROUTER_API_KEY`` is set the run uses it, so the catalog
is the account's entitled subset. Otherwise the run is deliberately
unauthenticated and hermetic (the key file and the catalog cache point at a
temporary directory), which is how CI reproduces it. The key itself is never
read, printed, or written by this script.

Run it from the repository root:

    python scripts/orcarouter_evidence.py

or through pytest:

    python -m pytest tests/integration/test_orcarouter_evidence.py
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

from doberman.dash import create_app
from doberman.providers.orcarouter import OrcaRouterProvider

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "orca-evidence"
VIEWPORT = {"width": 1280, "height": 900}
CHAT_CATALOG_URL = "https://api.orcarouter.ai/v1/models?capability=chat"
#: The browser strips ?token= from the address bar, so same-origin fetches made
#: from the page carry the per-run bearer token explicitly.
FETCH_JS = """async ([path, token]) => {
    const r = await fetch(path, {headers: {Authorization: 'Bearer ' + token}});
    return {status: r.status, body: await r.json()};
}"""
#: Read the rendered list container exactly as a user sees it.
DROPDOWN_JS = """() => {
    const list = document.getElementById('provider-model-list');
    const btn = document.getElementById('provider-model-btn');
    const cs = getComputedStyle(list);
    const b = btn.getBoundingClientRect();
    const l = list.getBoundingClientRect();
    return {
        open: !list.hidden,
        itemCount: list.querySelectorAll('li[role="option"]').length,
        background: cs.backgroundColor,
        borderWidth: cs.borderTopWidth,
        borderStyle: cs.borderTopStyle,
        triggerPanelRightDelta: Math.abs(b.right - l.right)
    };
}"""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _isolate_state() -> None:
    """Keep key/cache/settings out of the developer's home directory.

    With ``ORCAROUTER_API_KEY`` set, the env value wins and the catalog is the
    account's entitled subset. Without it the run must not silently pick up a
    stored key, so both files point into a per-run temp directory.
    """
    if os.environ.get("ORCAROUTER_API_KEY", "").strip():
        return
    sandbox = Path(tempfile.mkdtemp(prefix="orca-evidence-"))
    os.environ["DOBERMAN_ORCAROUTER_KEY_FILE"] = str(sandbox / "orcarouter.key")
    os.environ["DOBERMAN_ORCAROUTER_CACHE_FILE"] = str(sandbox / "orcarouter-models.json")
    os.environ["DOBERMAN_PROVIDER_FILE"] = str(sandbox / "providers.json")


def _serve_app(port: int, token: str) -> uvicorn.Server:
    # Serve the checkout's real dashboard code, but point its *data* root at a
    # throwaway directory: the dashboard opens the repo's ``.doberman`` store on
    # first use, and an evidence run must never create or touch that store in
    # the checkout it is documenting. The directory keeps the repository's name
    # so the shell shows the same project label it would in a real run.
    data_root = Path(tempfile.mkdtemp(prefix="orca-dash-")) / REPO.name
    data_root.mkdir()
    app = create_app(token, str(data_root), provider=OrcaRouterProvider())
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False)
    )
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2):  # noqa: S310
                return server
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    raise SystemExit("the dashboard never answered on its port")


def _open_list(page) -> None:
    page.click("#provider-model-btn")
    page.wait_for_function(
        "() => !document.getElementById('provider-model-list').hidden", timeout=15000
    )


def _close_list(page) -> None:
    page.click("#provider-model-btn")
    page.wait_for_function(
        "() => document.getElementById('provider-model-list').hidden", timeout=15000
    )


def _listed_ids(page) -> list[str]:
    return page.evaluate(
        """() => [...document.querySelectorAll('#provider-model-list li[role="option"]')]
            .map(li => li.dataset.modelId)"""
    )


def _dropdown_state(page) -> dict:
    state = page.evaluate(DROPDOWN_JS)
    state["opaque_background"] = state["background"] not in (
        "",
        "transparent",
        "rgba(0, 0, 0, 0)",
    )
    state["visible_border"] = state["borderWidth"] != "0px" and state["borderStyle"] != "none"
    return state


def _capture(port: int, token: str) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/usr/bin/chromium", headless=True)
        page = browser.new_page(viewport=VIEWPORT)
        page.goto(f"http://127.0.0.1:{port}/?token={token}", wait_until="networkidle")

        page.click("#provider-edit-btn")
        page.wait_for_selector("#provider-form:not([hidden])")
        page.wait_for_function(
            "() => document.querySelectorAll('#provider-select option').length > 0", timeout=20000
        )
        page.select_option("#provider-select", "orcarouter")
        page.wait_for_function(
            "() => !document.getElementById('provider-model-btn').disabled", timeout=20000
        )
        page.wait_for_timeout(800)

        catalog = page.evaluate(FETCH_JS, ["/api/providers?capability=chat", token])
        if catalog["status"] != 200:
            raise SystemExit(f"the providers API returned {catalog['status']}")
        body = catalog["body"]["catalog"]
        chat_ids = [model["id"] for model in body["models"]]

        # Auth methods: provider selector, masked key field, catalog controls.
        page.screenshot(path=str(OUT / "auth-methods.png"))
        state = page.evaluate(
            """() => {
                const key = document.getElementById('provider-key');
                return {
                    apiKeyVisible: !!key.offsetParent,
                    secretMasked: key.type === 'password',
                    controlsEnabled: !document.getElementById('provider-model-btn').disabled
                        && !document.getElementById('provider-refresh-btn').disabled,
                    provider: document.getElementById('provider-select').value
                };
            }"""
        )

        images = page.evaluate(FETCH_JS, ["/api/providers?capability=chat&modality=image", token])[
            "body"
        ]["catalog"]["models"]
        image_ids = [model["id"] for model in images]

        # The attachment toggle refetches against `modality=image`, so the same
        # control must narrow to the image-capable subset of the chat catalog.
        page.check("#provider-attach-image")
        page.wait_for_function(
            f"""() => /{len(image_ids)} models/.test(
                document.getElementById('provider-model-status').textContent)""",
            timeout=20000,
        )
        _open_list(page)
        narrowed = _listed_ids(page)
        image_dropdown = _dropdown_state(page)
        page.wait_for_timeout(300)
        page.screenshot(path=str(OUT / "multimodal-model-dropdown.png"))
        _close_list(page)

        page.uncheck("#provider-attach-image")
        page.wait_for_function(
            f"""() => /{len(chat_ids)} models/.test(
                document.getElementById('provider-model-status').textContent)""",
            timeout=20000,
        )
        _open_list(page)
        listed = _listed_ids(page)
        text_dropdown = _dropdown_state(page)
        page.wait_for_timeout(300)
        page.screenshot(path=str(OUT / "text-model-dropdown.png"))
        _close_list(page)
        browser.close()

    return {
        "source": body["source"],
        "chat_ids": chat_ids,
        "image_ids": image_ids,
        "narrowed": narrowed,
        "listed": listed,
        "text_dropdown": text_dropdown,
        "image_dropdown": image_dropdown,
        "state": state,
    }


def _ui_for_dropdown(state: dict) -> dict:
    return {
        "dropdown_open": state["open"],
        "item_count": state["itemCount"],
        "opaque_background": state["opaque_background"],
        "visible_border": state["visible_border"],
        "trigger_panel_right_delta": round(state["triggerPanelRightDelta"], 2),
    }


def _dropdown_ok(ui: dict, expected: int) -> bool:
    return (
        ui["dropdown_open"]
        and ui["item_count"] == expected
        and ui["opaque_background"]
        and ui["visible_border"]
        and ui["trigger_panel_right_delta"] <= 2
    )


def main() -> int:
    _isolate_state()
    port = _free_port()
    token = secrets.token_urlsafe(32)
    _serve_app(port, token)
    run = _capture(port, token)

    state = run["state"]
    auth_ui = {
        "api_key_visible": state["apiKeyVisible"],
        "secret_masked": state["secretMasked"],
        "controls_enabled": state["controlsEnabled"],
        "provider_selected": state["provider"],
    }
    text_ui = _ui_for_dropdown(run["text_dropdown"])
    image_ui = _ui_for_dropdown(run["image_dropdown"])

    catalog_ok = (
        sorted(run["listed"]) == sorted(run["chat_ids"])
        and sorted(run["narrowed"]) == sorted(run["image_ids"])
        and run["source"] == "live"
        and bool(run["chat_ids"])
        and bool(run["image_ids"])
    )
    passed = (
        auth_ui["api_key_visible"]
        and auth_ui["secret_masked"]
        and auth_ui["controls_enabled"]
        and auth_ui["provider_selected"] == "orcarouter"
        and catalog_ok
        and _dropdown_ok(text_ui, len(run["chat_ids"]))
        and _dropdown_ok(image_ui, len(run["image_ids"]))
    )

    artifacts = [
        {"kind": "auth-methods", "path": "auth-methods.png", "ui": auth_ui},
        {
            "kind": "text-model-dropdown",
            "path": "text-model-dropdown.png",
            "ui": text_ui,
        },
        {
            "kind": "multimodal-model-dropdown",
            "path": "multimodal-model-dropdown.png",
            "ui": image_ui,
        },
    ]
    for item in artifacts:
        path = OUT / item["path"]
        item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "automation": {
            "framework": "playwright",
            "passed": bool(passed),
            "catalog_source": CHAT_CATALOG_URL,
            "catalog_state": run["source"],
            "catalog_model_count": len(run["chat_ids"]),
            "image_model_count": len(run["image_ids"]),
        },
        "artifacts": artifacts,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
