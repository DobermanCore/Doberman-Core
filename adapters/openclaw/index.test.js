import { register } from "node:module";
import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";

const capturedPayloads = [];

globalThis.__openclawTestMocks = {
  reset() {
    capturedPayloads.length = 0;
  },
  getPayloads() {
    return capturedPayloads;
  },
  spawn(cmd, args, opts) {
    const child = new EventEmitter();
    const stdout = new EventEmitter();
    child.stdout = stdout;
    child.kill = () => {};

    let stdinData = "";
    child.stdin = {
      write(chunk) {
        stdinData += String(chunk);
        return true;
      },
      end(chunk) {
        if (chunk) stdinData += String(chunk);
        try {
          capturedPayloads.push(JSON.parse(stdinData));
        } catch {
          capturedPayloads.push(stdinData);
        }
        process.nextTick(() => {
          stdout.emit("data", JSON.stringify({ verdict: "allow" }));
          child.emit("close", 0);
        });
      },
    };

    return child;
  },
};

// Intercept OpenClaw plugin SDK and child_process.spawn without external dependencies
const loaderCode = `
export function resolve(specifier, context, nextResolve) {
  if (specifier === "openclaw/plugin-sdk/plugin-entry" || specifier.startsWith("openclaw/")) {
    return {
      format: "module",
      shortCircuit: true,
      url: "data:text/javascript," + encodeURIComponent("export function definePluginEntry(x) { return x; }"),
    };
  }
  if (specifier === "node:child_process" || specifier === "child_process") {
    const mockModuleCode = \`
      export function spawn(cmd, args, opts) {
        return globalThis.__openclawTestMocks.spawn(cmd, args, opts);
      }
    \`;
    return {
      format: "module",
      shortCircuit: true,
      url: "data:text/javascript," + encodeURIComponent(mockModuleCode),
    };
  }
  return nextResolve(specifier, context);
}
`;

register("data:text/javascript," + encodeURIComponent(loaderCode));

// Exercise the actual adapter implementation
const { default: pluginEntry } = await import("./index.js");

function createAdapterHooks(apiOverrides = {}) {
  const hooks = {};
  const mockApi = {
    on(name, handler) {
      if (apiOverrides[name]) {
        apiOverrides[name](name, handler);
      }
      hooks[name] = handler;
    },
  };
  pluginEntry.register(mockApi);
  return hooks;
}

beforeEach(() => {
  globalThis.__openclawTestMocks.reset();
});

test("payload uses mapped workspace directory as cwd instead of process.cwd()", async () => {
  const hooks = createAdapterHooks();
  const sessionId = "session-test-mapped-123";
  const tempProjectDir = "C:\\mock\\temp-project-workspace";

  // 1. Simulate before_agent_run with session ID and project directory
  hooks.before_agent_run({}, { sessionId, workspaceDir: tempProjectDir });

  // 2. Simulate before_tool_call with the same session ID
  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "npm test" } },
    { sessionId }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 1);
  const payload = payloads[0];

  assert.equal(payload.cwd, tempProjectDir);
  assert.notEqual(payload.cwd, process.cwd());
  assert.equal(payload.session_id, sessionId);
  assert.equal(payload.tool_name, "exec");
});

test("payload falls back to process.cwd() when mapping is unavailable for unknown session", async () => {
  const hooks = createAdapterHooks();
  const unknownSessionId = "session-unmapped-456";

  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "ls" } },
    { sessionId: unknownSessionId }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 1);
  const payload = payloads[0];

  assert.equal(payload.cwd, process.cwd());
  assert.equal(payload.session_id, unknownSessionId);
});

test("payload falls back to process.cwd() when context or sessionId is missing", async () => {
  const hooks = createAdapterHooks();

  // Missing ctx entirely
  await hooks.before_tool_call({ toolName: "exec", params: { command: "pwd" } });

  // ctx without sessionId
  await hooks.before_tool_call({ toolName: "exec", params: { command: "pwd" } }, {});

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 2);
  assert.equal(payloads[0].cwd, process.cwd());
  assert.equal(payloads[1].cwd, process.cwd());
});

test("payload falls back to process.cwd() after session_end removes the mapping", async () => {
  const hooks = createAdapterHooks();
  const sessionId = "session-ended-789";
  const tempProjectDir = "C:\\mock\\temp-project-workspace";

  // Register session workspace
  hooks.before_agent_run({}, { sessionId, workspaceDir: tempProjectDir });

  // End session
  hooks.session_end({}, { sessionId });

  // Tool call after session end
  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "git status" } },
    { sessionId }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 1);
  assert.equal(payloads[0].cwd, process.cwd());
});

test("ignores empty or whitespace-only workspace directory and falls back to process.cwd()", async () => {
  const hooks = createAdapterHooks();
  const sessionEmpty = "session-empty-dir";
  const sessionWhitespace = "session-whitespace-dir";

  // Attempt to register invalid workspace directories
  hooks.before_agent_run({}, { sessionId: sessionEmpty, workspaceDir: "" });
  hooks.before_agent_run({}, { sessionId: sessionWhitespace, workspaceDir: "   \t\n  " });

  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "ls" } },
    { sessionId: sessionEmpty }
  );
  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "ls" } },
    { sessionId: sessionWhitespace }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 2);
  assert.equal(payloads[0].cwd, process.cwd());
  assert.equal(payloads[1].cwd, process.cwd());
});

test("registers before_tool_call even if before_agent_run or session_end registration fails", async () => {
  const hooks = createAdapterHooks({
    before_agent_run() {
      throw new Error("simulated before_agent_run registration failure");
    },
    session_end() {
      throw new Error("simulated session_end registration failure");
    },
  });

  // Security hook before_tool_call must still be registered despite lifecycle hook errors
  assert.equal(typeof hooks.before_tool_call, "function");

  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "ls" } },
    { sessionId: "session-fallback" }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 1);
  assert.equal(payloads[0].cwd, process.cwd());
});

test("ignores non-string workspace directory and falls back to process.cwd()", async () => {
  const hooks = createAdapterHooks();
  const sessionId = "session-non-string-dir";

  // Simulate before_agent_run with a valid session ID but workspaceDir: 123
  hooks.before_agent_run({}, { sessionId, workspaceDir: 123 });

  // Call before_tool_call with the same session ID
  await hooks.before_tool_call(
    { toolName: "exec", params: { command: "ls" } },
    { sessionId }
  );

  const payloads = globalThis.__openclawTestMocks.getPayloads();
  assert.equal(payloads.length, 1);
  assert.equal(payloads[0].cwd, process.cwd());
  assert.equal(payloads[0].session_id, sessionId);
});
