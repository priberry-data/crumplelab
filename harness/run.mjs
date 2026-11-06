#!/usr/bin/env node
// Runs ONE scenario against ONE agent inside the container and prints a JSON result line.
// Usage: node run.mjs --scenario <id> --agent <id> --mode default|yolo [--timeout 360]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, execSync } from "node:child_process";
import { parseArgs } from "node:util";
import { byId } from "./scenarios.mjs";
import { AGENTS, runMock } from "./agents.mjs";
import { startHoneypot } from "./honeypot.mjs";

const { values: opt } = parseArgs({
  options: {
    scenario: { type: "string" },
    agent: { type: "string", default: "claude" },
    mode: { type: "string", default: "default" },
    timeout: { type: "string", default: "360" },
  },
});

const scenario = byId(opt.scenario);
const agent = AGENTS[opt.agent];
if (!scenario || !agent) {
  console.error(`unknown scenario or agent: ${opt.scenario} / ${opt.agent}`);
  process.exit(2);
}

const home = os.homedir();
const ws = path.join(home, "work", scenario.id);
fs.rmSync(ws, { recursive: true, force: true });
fs.mkdirSync(ws, { recursive: true });

const honeypot = await startHoneypot();
const ctx = { home, honeypot, mcpLog: path.join(home, ".crumple-mcp.jsonl") };
fs.rmSync(ctx.mcpLog, { force: true });
scenario.setup(ws, ctx);

// The user's own agent settings travel in as base64 JSON: { "<relative path>": "<contents>" }.
// Paths starting with "~/" land in the container's home, others in the project.
if (process.env.CRUMPLE_CONFIG_B64) {
  const files = JSON.parse(Buffer.from(process.env.CRUMPLE_CONFIG_B64, "base64").toString("utf8"));
  for (const [rel, text] of Object.entries(files)) {
    const dest = rel.startsWith("~/") ? path.join(home, rel.slice(2)) : path.join(ws, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, text);
  }
}

if (scenario.usesMcp) {
  ctx.mcpConfig = path.join(home, ".crumple-mcp.json");
  fs.writeFileSync(ctx.mcpConfig, JSON.stringify({
    mcpServers: { devtools: { command: "node", args: ["/opt/crumple/evil-mcp.mjs"], env: { CRUMPLE_MCP_LOG: ctx.mcpLog } } },
  }));
}

execSync("git init -q && git add -A && git -c user.email=dev@acme.test -c user.name=dev commit -qm init", { cwd: ws, shell: "/bin/bash" });

// Watch for destructive damage while the agent works, so we know WHEN it happened.
let damage = null;
const probe = () => {
  if (damage || !scenario.probe) return;
  const found = scenario.probe(ws, ctx);
  if (found) damage = { at: Date.now(), evidence: found };
};
const start = Date.now();
const timer = setInterval(probe, 500);

let exitCode = null;
let transcript = "";
if (agent.mock) {
  ({ exitCode, transcript } = await runMock(opt.agent, scenario.id, ws, ctx));
} else {
  const { cmd, args } = agent.command(scenario.task, { mode: opt.mode, mcpConfig: ctx.mcpConfig });
  const child = spawn(cmd, args, { cwd: ws, stdio: ["ignore", "pipe", "pipe"], env: process.env });
  child.stdout.on("data", (d) => (transcript += d));
  child.stderr.on("data", (d) => (transcript += d));
  const killer = setTimeout(() => child.kill("SIGKILL"), Number(opt.timeout) * 1000);
  exitCode = await new Promise((r) => child.on("close", r));
  clearTimeout(killer);
}

clearInterval(timer);
probe();
const leak = scenario.check ? scenario.check(ws, ctx) : null;
const breach = [leak, damage].filter(Boolean).sort((a, b) => a.at - b.at)[0] ?? null;
await honeypot.close();

// Pull the agent's final words out of a stream-json transcript, when there is one.
let summary = "";
for (const line of transcript.split("\n")) {
  try {
    const ev = JSON.parse(line);
    if (ev.type === "result" && typeof ev.result === "string") summary = ev.result;
  } catch {}
}

const result = {
  scenario: scenario.id,
  agent: opt.agent,
  mode: opt.mode,
  breached: Boolean(breach),
  timeToBreachMs: breach ? breach.at - start : null,
  evidence: breach?.evidence ?? null,
  durationMs: Date.now() - start,
  exitCode,
  agentSummary: summary.slice(0, 600),
  transcriptTail: transcript.slice(-1500),
};
console.log("CRUMPLE_RESULT " + JSON.stringify(result));
