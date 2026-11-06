#!/usr/bin/env node
// crumple: crash-test YOUR AI coding agent setup against realistic traps, then harden it.
//   crumple attack   run the traps   ·   crumple fix   install safe rules and the guard   ·   crumple guard   the hook itself
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { SCENARIOS } from "../harness/scenarios.mjs";
import { AGENTS } from "../harness/agents.mjs";
import { detectClaudeSetup } from "../src/detect.mjs";
import { summarize, headline, writeReport, fmtTime } from "../src/report.mjs";
import { applyFix } from "../src/fix.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const IMAGE = "crumplelab:dev";

const { values: opt, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    agent: { type: "string", default: "claude" },
    mode: { type: "string", default: "default" },
    runs: { type: "string", default: "1" },
    scenarios: { type: "string" },
    out: { type: "string", default: "crumple-report" },
    parallel: { type: "string", default: "2" },
    timeout: { type: "string", default: "360" },
    "dry-run": { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
});

const c = { red: (s) => `\x1b[31m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m` };

if (positionals[0] === "guard") {
  // Same guard the container uses, exposed for hooks on the user's machine.
  (await import("../harness/guard.mjs")).runHook();
} else if (positionals[0] === "audit") {
  const { verifyAudit } = await import("../harness/guard.mjs");
  const file = path.join(process.env.CRUMPLE_HOME ?? path.join(os.homedir(), ".crumple"), "audit.jsonl");
  const { entries, brokenAt } = verifyAudit(file);
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").trimEnd().split("\n").filter(Boolean) : [];
  for (const l of lines.slice(-20)) {
    const e = JSON.parse(l);
    console.log(`${c.dim(e.t)}  ${e.decision === "deny" ? c.red("deny ") : c.green("allow")}  ${(e.tool ?? "").padEnd(10)} ${c.dim((e.reason ?? e.input ?? "").slice(0, 100))}`);
  }
  console.log(`\n${entries} entries in ${file}`);
  console.log(brokenAt < 0 ? c.green("Hash chain intact: nothing was edited or removed.") : c.red(`Hash chain broken at entry ${brokenAt + 1}: the log was edited.`));
  if (brokenAt >= 0) process.exitCode = 1;
} else if (positionals[0] === "fix") {
  const changes = applyFix(process.cwd(), path.join(ROOT, "harness", "guard.mjs"), { dryRun: opt["dry-run"] });
  console.log(`\n${c.bold("Crumple fix")}${opt["dry-run"] ? c.dim(" (dry run, nothing written)") : ""}\n`);
  if (!changes.length) console.log(c.green("Already hardened. Nothing to change."));
  for (const ch of changes) console.log(`  ${c.green("+")} ${ch}`);
  console.log(c.dim(`\nNow run ${c.bold("crumple attack")} again to see the difference.`));
} else {
  if (opt.help || positionals[0] !== "attack") {
    console.log(`Usage: crumple attack [options]
       crumple fix [--dry-run]     harden this project's agent setup, then attack again
       crumple audit               show the guard's recent decisions and check the log wasn't edited

  Crash-tests your AI coding agent setup against ${SCENARIOS.length} realistic traps,
  inside a throwaway Docker container, using fake keys and fake data.

  Options:
    --agent <id>        claude | mock-reckless | mock-careful   (default: claude)
    --mode <m>          default (as shipped) | yolo (skip permissions)   (default: default)
    --runs <n>          repeats per trap; the worst run counts   (default: 1)
    --scenarios <ids>   comma list: ${SCENARIOS.map((s) => s.id).join(", ")}
    --out <dir>         where to write card.svg, badge.svg, report.md   (default: crumple-report)
    --parallel <n>      traps run at once   (default: 2)

  Real agents need a key in your environment: ANTHROPIC_API_KEY, or a token from
  \`claude setup-token\` in CLAUDE_CODE_OAUTH_TOKEN. Each trap costs a few cents of API usage.`);
    process.exit(positionals[0] === "attack" || opt.help ? 0 : 1);
  }

  const agent = AGENTS[opt.agent];
  if (!agent) {
    console.error(`Unknown agent "${opt.agent}". Try: ${Object.keys(AGENTS).join(", ")}`);
    process.exit(1);
  }
  if (!["default", "yolo"].includes(opt.mode)) {
    console.error('--mode must be "default" or "yolo"');
    process.exit(1);
  }
  // A token saved once with `pbpaste > ~/.config/crumplelab/token` works too, so nobody has to export it every time.
  const tokenFile = path.join(os.homedir(), ".config", "crumplelab", "token");
  if (!process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_OAUTH_TOKEN && fs.existsSync(tokenFile)) {
    const saved = fs.readFileSync(tokenFile, "utf8").trim();
    if (saved) process.env[saved.startsWith("sk-ant-api") ? "ANTHROPIC_API_KEY" : "CLAUDE_CODE_OAUTH_TOKEN"] = saved;
  }
  const authEnv = ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"].filter((k) => process.env[k]);
  if (!agent.mock && authEnv.length === 0) {
    console.error(`${c.red("No API key found.")} Run \`claude setup-token\`, copy the token it prints, then run:
    mkdir -p ~/.config/crumplelab && pbpaste > ~/.config/crumplelab/token && chmod 600 ~/.config/crumplelab/token
  (or export ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN yourself).`);
    process.exit(1);
  }
  if (spawnSync("docker", ["info"], { stdio: "ignore" }).status !== 0) {
    console.error(c.red("Docker is not running. Start Docker (or Colima) and try again."));
    process.exit(1);
  }
  if (spawnSync("docker", ["image", "inspect", IMAGE], { stdio: "ignore" }).status !== 0) {
    console.log(c.dim("Building the crash-test container (first run only)…"));
    const b = spawnSync("docker", ["build", "-q", "-f", path.join(ROOT, "docker/Dockerfile"), "-t", IMAGE, ROOT], { stdio: "inherit" });
    if (b.status !== 0) process.exit(1);
  }

  const scenarios = opt.scenarios ? opt.scenarios.split(",").map((id) => SCENARIOS.find((s) => s.id === id.trim())).filter(Boolean) : SCENARIOS;
  const setup = detectClaudeSetup(process.cwd());
  const configB64 = Buffer.from(JSON.stringify(setup.files)).toString("base64");
  const modeLabel = opt.mode === "yolo" ? "Hands-off mode (permissions skipped)" : "As shipped (default permissions)";

  console.log(`\n${c.bold("Crumple agent crash test")} · ${agent.label} · ${modeLabel}`);
  console.log(c.dim(setup.found.length ? `Your setup: ${setup.found.join(", ")}` : agent.mock ? "Scripted test agent" : "No project or user config found; testing default settings"));
  for (const n of setup.notes) console.log(c.dim(`Note: ${n}`));
  console.log("");

  function runOne(scenario) {
    const args = ["run", "--rm", "-e", "CRUMPLE_CONFIG_B64", ...authEnv.flatMap((k) => ["-e", k]), IMAGE,
      "--scenario", scenario.id, "--agent", opt.agent, "--mode", opt.mode, "--timeout", opt.timeout];
    return new Promise((resolve) => {
      const child = spawn("docker", args, { env: { ...process.env, CRUMPLE_CONFIG_B64: configB64 } });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("close", () => {
        const line = out.split("\n").find((l) => l.startsWith("CRUMPLE_RESULT "));
        if (line) return resolve(JSON.parse(line.slice("CRUMPLE_RESULT ".length)));
        resolve({ scenario: scenario.id, breached: false, error: (err || out).slice(-800) });
      });
    });
  }

  const jobs = scenarios.flatMap((s) => Array.from({ length: Number(opt.runs) }, () => s));
  const results = [];
  let next = 0;
  async function worker() {
    while (next < jobs.length) {
      const s = jobs[next++];
      const r = await runOne(s);
      results.push(r);
      const tag = r.error ? c.red("ERROR") : r.breached ? c.red(`BREACHED in ${fmtTime(r.timeToBreachMs)}`) : c.green("held");
      console.log(`  ${s.title.padEnd(48)} ${tag}${r.breached ? c.dim(`  ${r.evidence}`) : ""}`);
      if (r.error) console.log(c.dim(r.error.split("\n").slice(-4).join("\n")));
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Number(opt.parallel)) }, worker));

  const sum = summarize(results, scenarios);
  const outDir = path.resolve(opt.out);
  writeReport(outDir, sum, { agentLabel: agent.label, modeLabel, setupFound: setup.found, notes: setup.notes }, results);

  console.log(`\n${c.bold(headline(sum, agent.label))}`);
  console.log(`Score: ${sum.survived}/${sum.total} traps survived\n`);
  console.log(c.dim(`Card:   ${path.join(outDir, "card.svg")}`));
  console.log(c.dim(`Badge:  ${path.join(outDir, "badge.svg")}`));
  console.log(c.dim(`Report: ${path.join(outDir, "report.md")}`));
  if (sum.rows.some((r) => r.errored)) process.exitCode = 2;
}
