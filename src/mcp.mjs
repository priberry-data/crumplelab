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
    name: "crumple_site",
    description: "Grade a deployed web app (built with Lovable, Bolt, v0, Replit, Emergent or by hand) A to F for what a stranger can use against it: secret keys shipped in its JavaScript, a Supabase service_role key in the browser, public source maps, no Content-Security-Policy. Each finding has a plain-English reason, what the owner must do by hand (like revoking a key), and a fix `prompt` to apply in the app's code. Call it again after fixing: `change` lists what got fixed. Reads only what the site serves to every visitor. Database checks (which Supabase tables or Firebase data anyone can read) need the owner, so tell them to run `npx crumplelab site <url> --mine` themselves.",
    inputSchema: { type: "object", properties: { url: { type: "string", description: "The app's address, for example myapp.lovable.app" } }, required: ["url"], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "crumple_traps",
    description: "The traps Crumple's crash test runs: each modelled on a real attack (poisoned issues, evil MCP servers, secret exfiltration, destructive commands), with its risk.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
];

const lastSite = new Map();

async function call(name, args = {}) {
  if (name === "crumple_scan") {
    const dir = path.resolve(args.path || process.cwd());
    return { project: dir, ...scan(dir), next: "Run `npx crumplelab fix` to harden, then `npx crumplelab attack` to prove it (needs Docker and an API key)." };
  }
  if (name === "crumple_site") {
    const { siteScan, compare } = await import("./site.mjs");
    const result = await siteScan(args.url, { mine: false });
    // Remembered for this session only, so a second call shows what the fixes changed.
    const change = compare(lastSite.get(result.url), result);
    lastSite.set(result.url, { at: new Date().toISOString(), score: result.score, grade: result.grade, findings: result.findings.map(({ id, severity, title }) => ({ id, severity, title })) });
    return { ...result, change };
  }
  if (name === "crumple_traps") return { traps: SCENARIOS.map((s) => ({ id: s.id, title: s.title, risk: s.risk })) };
  throw new Error(`unknown tool ${name}`);
}

export function serve({ version, input = process.stdin, output = process.stdout } = {}) {
  const send = (msg) => output.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  const pending = new Set();
  rl.on("line", (line) => {
    const job = handle(line).finally(() => pending.delete(job));
    pending.add(job);
  });
  async function handle(line) {
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
        const r = await call(m.params?.name, m.params?.arguments);
        return send({ id: m.id, result: { content: [{ type: "text", text: JSON.stringify(r, null, 2) }], structuredContent: r } });
      } catch (e) {
        return send({ id: m.id, result: { content: [{ type: "text", text: `crumple: ${e.message}` }], isError: true } });
      }
    }
    send({ id: m.id, error: { code: -32601, message: `method not found: ${m.method}` } });
  }
  // Let calls still running (a site check takes seconds) answer before the server exits.
  return new Promise((resolve) => rl.on("close", () => Promise.allSettled([...pending]).then(resolve)));
}
