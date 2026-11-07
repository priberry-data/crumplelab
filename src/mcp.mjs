// Crumple as an MCP server (stdio, newline-delimited JSON-RPC). It exposes only what is instant and
// local: the setup scan and the trap list. The full crash test runs real agents in Docker and spends
// API credit, so it stays a command the person runs on purpose.
import path from "node:path";
import readline from "node:readline";
import { scan } from "./scan.mjs";
import { SCENARIOS } from "../harness/scenarios.mjs";

const TOOLS = [
  {
    name: "crumple_scan",
    description: "Audit an AI coding agent setup (Claude Code, Codex, Gemini CLI, Cursor, MCP config, hooks, CLAUDE.md/AGENTS.md, .env exposure) the way an attacker would. Local and instant: no key, no Docker, nothing leaves the machine. Returns a 0-100 Safe Setup score and findings, each with why it matters and the fix.",
    inputSchema: { type: "object", properties: { path: { type: "string", description: "Project folder to scan. Defaults to the server's working directory." } }, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "crumple_traps",
    description: "The traps Crumple's crash test runs: each modelled on a real attack (poisoned issues, evil MCP servers, secret exfiltration, destructive commands), with its risk.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
];

function call(name, args = {}) {
  if (name === "crumple_scan") {
    const dir = path.resolve(args.path || process.cwd());
    return { project: dir, ...scan(dir), next: "Run `npx crumplelab fix` to harden, then `npx crumplelab attack` to prove it (needs Docker and an API key)." };
  }
  if (name === "crumple_traps") return { traps: SCENARIOS.map((s) => ({ id: s.id, title: s.title, risk: s.risk })) };
  throw new Error(`unknown tool ${name}`);
}

export function serve({ version, input = process.stdin, output = process.stdout } = {}) {
  const send = (msg) => output.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  rl.on("line", (line) => {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return send({ id: null, error: { code: -32700, message: "parse error" } });
    }
    if (m.id === undefined) return;
    if (m.method === "initialize")
      return send({ id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "crumple", version } } });
    if (m.method === "ping") return send({ id: m.id, result: {} });
    if (m.method === "tools/list") return send({ id: m.id, result: { tools: TOOLS } });
    if (m.method === "tools/call") {
      try {
        const r = call(m.params?.name, m.params?.arguments);
        return send({ id: m.id, result: { content: [{ type: "text", text: JSON.stringify(r, null, 2) }], structuredContent: r } });
      } catch (e) {
        return send({ id: m.id, result: { content: [{ type: "text", text: `crumple: ${e.message}` }], isError: true } });
      }
    }
    send({ id: m.id, error: { code: -32601, message: `method not found: ${m.method}` } });
  });
  return new Promise((resolve) => rl.on("close", resolve));
}
