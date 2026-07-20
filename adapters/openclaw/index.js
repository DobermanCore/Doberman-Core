// Doberman <-> OpenClaw bridge.
//
// Registers a `before_tool_call` plugin hook that spawns a fresh
// `doberman hook openclaw` process per call, writes the event as JSON on
// stdin, and reads exactly one JSON verdict back from stdout. See
// ../../src/doberman/hosthooks/openclaw.py for the Python side of this
// contract, and README.md (this directory) for install steps and the
// mandatory "verify it's live" canary check.
//
// FAIL-CLOSED IS THE INVARIANT: any spawn failure, timeout, non-zero exit, or
// unparseable stdout returns `{ block: true, blockReason: "..." }` - never a
// silent allow. See README.md "Known limitations" for the platform-level
// fail-open gap this can't cover (openclaw/openclaw#20914 - a failed plugin
// *load* silently disables the whole hook, hence the canary requirement).

import { spawn } from "node:child_process";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

// Doberman's own subprocess deadline. Kept comfortably under HOOK_TIMEOUT_MS
// below so OUR fail-closed return always wins the race before OpenClaw's own
// hook-timeout handling could apply.
// ponytail: one constant, no options plumbing.
const DOBERMAN_TIMEOUT_MS = 10_000;

// Headroom above DOBERMAN_TIMEOUT_MS for process spawn/IO overhead, handed to
// OpenClaw as this hook's own await budget (api.on's `timeoutMs` option).
const HOOK_TIMEOUT_MS = 15_000;

const FAIL_CLOSED_REASON = "doberman unavailable - failing closed";

function failClosed(reason) {
  return { block: true, blockReason: reason };
}

/**
 * Ask `doberman hook openclaw` for a verdict on one tool call.
 * Never rejects/throws - resolves `null` on any failure so the caller can
 * fail closed.
 */
function askDoberman(payload) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn("doberman", ["hook", "openclaw"], {
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      resolve(null);
      return;
    }

    let stdout = "";
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(null);
    }, DOBERMAN_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.on("error", () => finish(null));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(null);
        return;
      }
      try {
        finish(JSON.parse(stdout));
      } catch {
        finish(null);
      }
    });

    try {
      child.stdin.write(JSON.stringify(payload));
      child.stdin.end();
    } catch {
      finish(null);
    }
  });
}

/** Map Doberman's `{verdict: ...}` wire format to OpenClaw's BeforeToolCallResult. */
function toHookResult(verdict) {
  if (verdict === null || typeof verdict !== "object") {
    return failClosed(FAIL_CLOSED_REASON);
  }
  switch (verdict.verdict) {
    case "allow":
      // Raise-only: Doberman never overrides an approval OpenClaw would
      // otherwise grant, so "allow" is a plain no-op.
      return {};
    case "block":
      return failClosed(verdict.reason || FAIL_CLOSED_REASON);
    case "auth":
      return {
        requireApproval: {
          title: verdict.title || "Doberman approval required",
          description: verdict.description || "",
          severity: verdict.severity || "warning",
          timeoutMs: verdict.timeout_ms || 300_000,
          // Deliberately no "allow-always": a standing approval is
          // Doberman's own policy surface, not something to memorize here.
          allowedDecisions: ["allow-once", "deny"],
        },
      };
    default:
      return failClosed(FAIL_CLOSED_REASON);
  }
}

export default definePluginEntry({
  id: "doberman",
  name: "Doberman",
  description: "Routes every tool call through Doberman's PASS/AUTH/BLOCK decision engine.",
  register(api) {
    // Canary companion: confirms the plugin loaded and registered at all.
    // Absence of this line at gateway startup means interception is NOT
    // active - see README.md's "Verify it's live" section.
    console.log("[doberman] interception active - before_tool_call hook registered");

    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const payload = {
          tool_name: event?.toolName,
          params: event?.params,
          derived_paths: event?.derivedPaths,
          cwd: process.cwd(),
          session_id: ctx?.sessionId,
        };
        const verdict = await askDoberman(payload);
        return toHookResult(verdict);
      },
      { timeoutMs: HOOK_TIMEOUT_MS },
    );
  },
});
