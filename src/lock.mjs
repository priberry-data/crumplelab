// crumple lock: pins what every MCP server tells your agent. It starts each local server once,
// records each tool's name, description and input schema as a hash, and later reports any tool
// that appeared or changed (the MCP "rug pull"). The guard refuses calls to tools not in the lock.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";

export const LOCK_PATH = (dir) => path.join(dir, ".crumple", "mcp.lock.json");

function servers(projectDir, home) {
  const out = {};
  for (const f of [path.join(projectDir, ".mcp.json"), path.join(home, ".claude.json")]) {
    try {
      const cfg = JSON.parse(fs.readFileSync(f, "utf8"));
      Object.assign(out, cfg.mcpServers ?? {});
      Object.assign(out, cfg.projects?.[projectDir]?.mcpServers ?? {});
    } catch {}
  }
  return out;
}

// Speaks just enough MCP over stdio to list tools.
function listTools(srv, timeoutMs = 20000) {
  return new Promise((resolve) => {
    if (!srv.command) return resolve({ error: "remote servers are not locked yet" });
    const child = spawn(srv.command, srv.args ?? [], { env: { ...process.env, ...srv.env }, stdio: ["pipe", "pipe", "ignore"] });
    let buf = "";
    const done = (v) => {
      clearTimeout(timer);
      child.kill();
      resolve(v);
    };
    const timer = setTimeout(() => done({ error: "timed out" }), timeoutMs);
    child.on("error", (e) => done({ error: e.message }));
    child.stdout.on("data", (d) => {
      buf += d;
      for (const line of buf.split("\n")) {
        try {
          const m = JSON.parse(line);
          if (m.id === 2) return done({ tools: m.result?.tools ?? [] });
        } catch {}
      }
    });
    const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "crumple-lock", version: "1" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  });
}

const hashTool = (t) => crypto.createHash("sha256").update(JSON.stringify([t.name, t.description ?? "", t.inputSchema ?? {}])).digest("hex");

export async function snapshot(projectDir, home = os.homedir()) {
  const result = {};
  for (const [name, srv] of Object.entries(servers(projectDir, home))) {
    const r = await listTools(srv);
    result[name] = r.error ? { error: r.error } : { command: [srv.command, ...(srv.args ?? [])].join(" "), tools: Object.fromEntries(r.tools.map((t) => [t.name, hashTool(t)])) };
  }
  return result;
}

export function diff(locked, now) {
  const changes = [];
  for (const [name, s] of Object.entries(now)) {
    const was = locked[name];
    if (!was) { changes.push(`new server "${name}"`); continue; }
    if (s.error || was.error) continue;
    if (s.command !== was.command) changes.push(`"${name}" now runs a different command: ${s.command}`);
    for (const [tool, h] of Object.entries(s.tools)) {
      if (!(tool in was.tools)) changes.push(`"${name}" added a tool: ${tool}`);
      else if (was.tools[tool] !== h) changes.push(`"${name}" changed what the tool ${tool} says or accepts`);
    }
  }
  return changes;
}
