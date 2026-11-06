#!/usr/bin/env node
// crumple: crash-test YOUR AI coding agent setup against realistic traps, then harden it.
//   crumple attack   run the traps   ·   crumple fix   install safe rules and the guard   ·   crumple guard   the hook itself
import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { SCENARIOS, loadPacks } from "../harness/scenarios.mjs";
import { AGENTS } from "../harness/agents.mjs";
import { detectClaudeSetup } from "../src/detect.mjs";
import { summarize, headline, writeReport, fmtTime } from "../src/report.mjs";
import { applyFix } from "../src/fix.mjs";
import { banner } from "../src/banner.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version: VERSION } = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
// The image is tagged with the version and a hash of everything copied into it,
// so a changed harness always gets a fresh container and an old one is never reused by mistake.
const IMAGE = (() => {
  const h = crypto.createHash("sha256");
  for (const dir of ["harness", "docker"])
    for (const f of fs.readdirSync(path.join(ROOT, dir)).sort()) h.update(f).update(fs.readFileSync(path.join(ROOT, dir, f)));
  return `crumplelab:${VERSION}-${h.digest("hex").slice(0, 10)}`;
})();

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
    sandbox: { type: "boolean" },
    managed: { type: "boolean" },
    check: { type: "boolean" },
    json: { type: "boolean" },
    sarif: { type: "string" },
    "fail-on": { type: "string" },
    pack: { type: "string", multiple: true, default: [] },
    help: { type: "boolean", short: "h" },
  },
});

const c = { red: (s) => `\x1b[31m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m` };

// The guard speaks JSON to the agent over stdout, so it (and any machine-readable output) never gets the banner.
if (!["guard", "audit"].includes(positionals[0]) && !opt.json) process.stdout.write(banner({ version: VERSION, tagline: "the crash test for AI coding agents" }));

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
} else if (positionals[0] === "list") {
  const { tags } = await import("../harness/standards.mjs");
  const all = [...SCENARIOS, ...(await loadPacks(opt.pack.map((p) => path.resolve(p))))];
  for (const s of all) console.log(`${c.bold(s.id.padEnd(20))} ${s.title}${s.pack ? c.dim(` [pack: ${s.pack}]`) : ""}\n${" ".repeat(21)}${c.dim(`${s.risk} · ${tags(s).join(" ")}`)}`);
  console.log(`\n${all.length} traps`);
} else if (positionals[0] === "scan") {
  const { scan, toSarif, SEVERITY } = await import("../src/scan.mjs");
  const result = scan(process.cwd());
  if (opt.sarif) fs.writeFileSync(opt.sarif, JSON.stringify(toSarif(result), null, 2) + "\n");
  if (opt.json) console.log(JSON.stringify(result, null, 2));
  else {
    const col = { critical: c.red, high: c.red, medium: c.yellow, low: c.dim };
    console.log(`\n${c.bold("Crumple scan")} · ${process.cwd()}\n`);
    for (const f of result.findings) {
      console.log(`${col[f.severity](f.severity.toUpperCase().padEnd(8))} ${c.bold(f.title)} ${c.dim(`(${f.where})`)}`);
      console.log(`         ${f.why}`);
      console.log(`         ${c.green("Fix:")} ${f.fix}\n`);
    }
    const color = result.score >= 75 ? c.green : result.score >= 55 ? c.yellow : c.red;
    console.log(`Safe Setup score: ${color(`${result.score}/100 (${result.grade})`)} · ${result.findings.length} findings · nothing left this machine`);
    console.log(c.dim("Next: `crumple fix` to harden, then `crumple attack` to prove it."));
  }
  const failOn = opt["fail-on"];
  if (failOn && result.findings.some((f) => SEVERITY[f.severity] >= SEVERITY[failOn])) process.exitCode = 1;
} else if (positionals[0] === "lock") {
  const { snapshot, diff, LOCK_PATH } = await import("../src/lock.mjs");
  const file = LOCK_PATH(process.cwd());
  const now = await snapshot(process.cwd());
  if (opt.check) {
    const locked = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")).servers : null;
    if (!locked) {
      console.log(c.red("No MCP lock yet. Run `crumple lock` first."));
      process.exitCode = 1;
    } else {
      const changes = diff(locked, now);
      for (const ch of changes) console.log(`  ${c.red("!")} ${ch}`);
      console.log(changes.length ? c.red(`\n${changes.length} change(s) since the lock. Review them before your agent uses these servers.`) : c.green("All MCP servers still match the lock."));
      if (changes.length) process.exitCode = 1;
    }
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ created: new Date().toISOString(), servers: now }, null, 2) + "\n");
    for (const [n, s] of Object.entries(now)) console.log(`  ${s.error ? c.yellow("~") : c.green("+")} ${n}: ${s.error ?? `${Object.keys(s.tools).length} tools pinned`}`);
    console.log(c.dim(`\nWrote ${path.relative(process.cwd(), file)}. The guard now refuses tools that aren't in it.`));
  }
} else if (positionals[0] === "fix") {
  const changes = applyFix(process.cwd(), path.join(ROOT, "harness", "guard.mjs"), { dryRun: opt["dry-run"], sandbox: opt.sandbox });
  console.log(`\n${c.bold("Crumple fix")}${opt["dry-run"] ? c.dim(" (dry run, nothing written)") : ""}\n`);
  if (!changes.length) console.log(c.green("Already hardened. Nothing to change."));
  for (const ch of changes) console.log(`  ${c.green("+")} ${ch}`);
  if (opt.managed) {
    const { managedSettings } = await import("../src/fix.mjs");
    const { MANAGED_SETTINGS } = await import("../src/detect.mjs");
    // Copy the guard somewhere only an admin can change, then point managed settings at it.
    const guardHome = process.platform === "darwin" ? "/Library/Application Support/ClaudeCode/crumple" : "/etc/claude-code/crumple";
    const draft = path.resolve("crumple-managed-settings.json");
    fs.writeFileSync(draft, JSON.stringify(managedSettings(path.join(guardHome, "guard.mjs")), null, 2) + "\n");
    console.log(`\n  ${c.green("+")} ${path.basename(draft)}: managed settings that only allow your own hooks and lock the guard in place`);
    console.log(c.dim("\n  Installing them needs an admin password, so run these yourself:"));
    console.log(`    sudo mkdir -p "${guardHome}" && sudo cp "${path.join(ROOT, "harness")}"/{guard,shell}.mjs "${guardHome}/"`);
    console.log(`    sudo cp "${draft}" "${MANAGED_SETTINGS}"`);
  }
  console.log(c.dim(`\nNow run ${c.bold("crumple attack")} again to see the difference.`));
} else {
  if (opt.help || positionals[0] !== "attack") {
    console.log(`Usage: crumple attack [options]
       crumple scan [--sarif f] [--fail-on high]   instant local audit of your agent setup (no key, no Docker)
       crumple fix [--sandbox] [--managed] [--dry-run]   harden this project's agent setup, then attack again
       crumple lock [--check]                      pin your MCP servers' tools; report any that change
       crumple list [--pack dir]                   every trap, its source and the standards it maps to
       crumple audit               show the guard's recent decisions and check the log wasn't edited

  Crash-tests your AI coding agent setup against ${SCENARIOS.length} realistic traps,
  inside a throwaway Docker container, using fake keys and fake data.

  Options:
    --agent <id>        claude | codex | gemini | mock-reckless | mock-careful   (default: claude)
    --mode <m>          default (as shipped) | yolo (skip permissions)   (default: default)
    --runs <n>          repeats per trap; the worst run counts   (default: 1)
    --scenarios <ids>   comma list: ${SCENARIOS.map((s) => s.id).join(", ")}
    --pack <dir>        add a folder of extra traps (repeatable)
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
  const authEnv = (agent.auth ?? []).filter((k) => process.env[k]);
  if (!agent.mock && opt.agent !== "claude" && authEnv.length === 0) {
    console.error(`${c.red("No API key found")} for ${agent.label}. Export one of: ${agent.auth.join(", ")}`);
    process.exit(1);
  }
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

  const packDirs = opt.pack.map((p) => path.resolve(p));
  const all = [...SCENARIOS, ...(await loadPacks(packDirs))];
  const scenarios = opt.scenarios ? opt.scenarios.split(",").map((id) => all.find((s) => s.id === id.trim())).filter(Boolean) : all;
  // Packs are mounted read-only and loaded by the same code inside the container.
  const packMounts = packDirs.flatMap((d, i) => ["-v", `${d}:/opt/crumple-packs/${i}:ro`]);
  const packArgs = packDirs.flatMap((_, i) => ["--pack", `/opt/crumple-packs/${i}`]);
  const setup = detectClaudeSetup(process.cwd());
  const configB64 = Buffer.from(JSON.stringify(setup.files)).toString("base64");
  const modeLabel = opt.mode === "yolo" ? "Hands-off mode (permissions skipped)" : "As shipped (default permissions)";

  console.log(`\n${c.bold("Crumple agent crash test")} · ${agent.label} · ${modeLabel}`);
  console.log(c.dim(setup.found.length ? `Your setup: ${setup.found.join(", ")}` : agent.mock ? "Scripted test agent" : "No project or user config found; testing default settings"));
  for (const n of setup.notes) console.log(c.dim(`Note: ${n}`));
  console.log("");

  function runOne(scenario) {
    // All DNS goes to Crumple's resolver inside the container; no extra privileges, bounded resources.
    const args = ["run", "--rm", "--dns", "127.0.0.1", "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "3g", ...packMounts, "-e", "CRUMPLE_CONFIG_B64", ...authEnv.flatMap((k) => ["-e", k]), IMAGE,
      "--scenario", scenario.id, "--agent", opt.agent, "--mode", opt.mode, "--timeout", opt.timeout, ...packArgs];
    return new Promise((resolve) => {
      const child = spawn("docker", args, { env: { ...process.env, CRUMPLE_CONFIG_B64: configB64 } });
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("close", () => {
        const line = out.split("\n").find((l) => l.startsWith("CRUMPLE_RESULT "));
        if (line) return resolve(JSON.parse(line.slice("CRUMPLE_RESULT ".length)));
        resolve({ scenario: scenario.id, breached: false, hijacked: false, error: (err || out).slice(-800) });
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
      const tag = r.error ? c.red("ERROR") : r.breached ? c.red(`BREACHED in ${fmtTime(r.timeToBreachMs)}`) : r.hijacked ? c.yellow("hijacked, contained") : c.green("held");
      console.log(`  ${s.title.padEnd(52)} ${tag}${r.breached || r.hijacked ? c.dim(`  ${r.evidence}`) : ""}`);
      if (r.error) console.log(c.dim(r.error.split("\n").slice(-4).join("\n")));
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Number(opt.parallel)) }, worker));

  const sum = summarize(results, scenarios);
  const outDir = path.resolve(opt.out);
  writeReport(outDir, sum, { agentLabel: agent.label, modeLabel, setupFound: setup.found, notes: setup.notes }, results);

  console.log(`\n${c.bold(headline(sum, agent.label))}`);
  console.log(`Score: ${sum.survived}/${sum.total} traps survived${sum.hijacked ? ` · ${sum.hijacked} hijacked but contained` : ""}\n`);
  console.log(c.dim(`Card:   ${path.join(outDir, "card.svg")}`));
  console.log(c.dim(`Badge:  ${path.join(outDir, "badge.svg")}`));
  console.log(c.dim(`Report: ${path.join(outDir, "report.md")}`));
  if (sum.rows.some((r) => r.errored)) process.exitCode = 2;
}
