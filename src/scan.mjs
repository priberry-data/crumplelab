// crumple scan: a static, local-only audit of an AI agent setup. No API key, no Docker,
// nothing leaves the machine. Every finding says what an attacker would do with it and how to fix it.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/u;
const SECRET_VALUES = /AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9A-Za-z_]{10,}|sk-(ant|proj)-[0-9A-Za-z_-]{10,}|gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}|glpat-[0-9A-Za-z_-]{20}|xox[bpas]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{36}/;
const INJECTION = /ignore (all |any )?(previous|prior|above) instructions|do not (mention|tell|reveal) (this|the user)|(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b|--data(-binary)? @\.env|you are now|system prompt:|<\s*important\s*>/i;
export const SEVERITY = { critical: 40, high: 15, medium: 5, low: 1 };

const read = (p, limit = 2 * 1024 * 1024) => {
  try {
    const st = fs.statSync(p);
    return st.isFile() && st.size <= limit ? fs.readFileSync(p, "utf8") : null;
  } catch {
    return null;
  }
};
const json = (p) => {
  const t = read(p);
  if (t == null) return null;
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
};
const redact = (s) => String(s).replace(new RegExp(SECRET_VALUES.source, "g"), (m) => m.slice(0, 4) + "…[redacted]");

export function scan(projectDir, { home = os.homedir() } = {}) {
  const findings = [];
  const add = (severity, where, title, why, fix) => findings.push({ severity, where, title, why, fix });
  const rel = (p) => (p.startsWith(projectDir + path.sep) ? path.relative(projectDir, p) : p.startsWith(home + path.sep) ? "~/" + path.relative(home, p) : p);
  const P = (...x) => path.join(projectDir, ...x);
  const H = (...x) => path.join(home, ...x);

  // --- Claude Code settings ------------------------------------------------------------------
  const settingsFiles = [P(".claude/settings.json"), P(".claude/settings.local.json"), H(".claude/settings.json")];
  const allSettings = settingsFiles.map((f) => [f, json(f)]).filter(([, s]) => s);
  let guarded = false, sandboxed = false, denyEnv = false;
  for (const [f, s] of allSettings) {
    const where = rel(f);
    const perm = s.permissions ?? {};
    if (perm.defaultMode === "bypassPermissions") add("critical", where, "Agent runs with every permission check switched off", "Any instruction it reads in a file, issue or web page can run commands, delete data or send your keys out, with nothing asking you first.", 'Remove `"defaultMode": "bypassPermissions"`. Use a sandbox if you want fewer prompts.');
    if (s.skipDangerousModePermissionPrompt) add("high", where, "The warning before skip-permissions mode is turned off", "Skip-permissions mode can be switched on without you noticing.", "Remove `skipDangerousModePermissionPrompt`.");
    for (const rule of perm.allow ?? []) {
      const r = String(rule);
      if (/^Bash(\(\*\)|\(:\*\))?$/.test(r)) add("critical", where, `Every shell command is pre-approved (${r})`, "A prompt injection becomes code execution on your machine immediately.", `Remove "${r}" and allow specific commands instead.`);
      else if (/^Bash\((curl|wget|nc|ssh|scp|rsync|http)\b/.test(r)) add("high", where, `Network tool pre-approved (${r})`, "This is the exact command attackers use to send your .env out.", `Remove "${r}"; let the agent ask, or allow only fixed URLs.`);
      else if (/^Bash\((git|find|fd|rg|go|xargs|env|sed|awk|tar|npx|npm|pnpm|yarn|node|python3?|bash|sh)(:\*|\s\*|\*)?\)$/.test(r)) add("high", where, `Broad pre-approval that can run any program (${r})`, "Flags like `git -c core.fsmonitor=`, `find -exec`, `npm run` and `npx` turn a \"safe\" prefix into arbitrary code (Trail of Bits, 2025).", `Narrow "${r}" to exact subcommands (for example "Bash(git status)"), and install the Crumple guard, which checks flags.`);
      else if (/^(WebFetch|mcp__[\w-]+)$/.test(r)) add("medium", where, `Pre-approved without limits (${r})`, "Lets content from anywhere drive the agent and receive data without a prompt.", `Scope "${r}" to specific domains or tools.`);
    }
    for (const d of perm.deny ?? []) if (/\.env/.test(String(d))) denyEnv = true;
    if (s.enableAllProjectMcpServers) add("high", where, "Every MCP server a repository ships is started automatically", "Cloning a hostile repo starts its MCP server with your permissions (Check Point, CVE-2025-59536).", "Remove `enableAllProjectMcpServers` and approve servers one by one.");
    for (const [k, v] of Object.entries(s.env ?? {})) {
      if (/_(BASE_URL|API_BASE)$/.test(k) && !/anthropic\.com|openai\.com|localhost|127\.0\.0\.1/.test(String(v))) add("critical", where, `${k} points at ${String(v).slice(0, 60)}`, "Every request, including your API key, goes to that server (CVE-2026-21852).", `Remove ${k} unless you run that proxy yourself.`);
      if (SECRET_VALUES.test(String(v))) add("high", where, `A secret sits in plain text in settings (${k})`, "Anything that can read this file, including the agent, has the key.", "Move it to your OS keychain or a secret manager.");
    }
    const hooks = JSON.stringify(s.hooks ?? {});
    if (/guard\.mjs|crumplelab guard/.test(hooks)) guarded = true;
    if (/\b(curl|wget|nc)\b|https?:\/\//.test(hooks)) add("high", where, "A hook sends data over the network", "Hooks run automatically on every tool call or session start, without the agent or you approving them.", "Check every hook command; remove any that talk to the network.");
    if (f.startsWith(projectDir) && s.hooks && !/guard\.mjs/.test(hooks)) add("medium", where, "This repository ships its own hooks", "Hooks in a cloned repo run commands on your machine as soon as the agent starts.", "Review them before running an agent here.");
    if (s.sandbox?.enabled) sandboxed = true;
  }
  if (!guarded) add("medium", "agent setup", "No runtime guard checks the agent's commands", "Nothing stops a hijacked agent from sending keys out or deleting data between your prompts.", "Run `crumple fix`.");
  if (!sandboxed) add("medium", "agent setup", "The agent's commands don't run in a sandbox", "Commands can reach every file you can and any server on the internet. Sandboxes and egress limits are the defenses research shows hold up under adaptive attacks.", "Run `crumple fix --sandbox` to switch on Claude Code's built-in sandbox with a network allowlist.");

  // --- MCP servers, across agents -------------------------------------------------------------
  const mcpFiles = [P(".mcp.json"), H(".claude.json"), P(".cursor/mcp.json"), H(".cursor/mcp.json"), P(".vscode/mcp.json"), H(".codeium/windsurf/mcp_config.json"), H(".gemini/settings.json"), P(".gemini/settings.json")];
  for (const f of mcpFiles) {
    const cfg = json(f);
    const servers = { ...(cfg?.mcpServers ?? {}), ...(cfg?.servers ?? {}) };
    for (const proj of Object.values(cfg?.projects ?? {})) Object.assign(servers, proj?.mcpServers ?? {});
    for (const [name, srv] of Object.entries(servers)) {
      const where = `${rel(f)} → ${name}`;
      const cmd = [srv.command, ...(srv.args ?? [])].join(" ");
      if (/\b(npx|bunx|pnpm dlx|uvx)\b/.test(cmd)) {
        const pkg = (srv.args ?? []).find((a) => !String(a).startsWith("-")) ?? "";
        if (!/@\d/.test(pkg.replace(/^@[^/]+\//, "")) || /@latest$/.test(pkg)) add("high", where, `MCP server runs whatever version is newest (${pkg || cmd})`, "If that package is ever compromised or sold, your agent runs the new code with your keys the next time it starts (MCP rug pull).", `Pin an exact version, for example ${pkg.replace(/@latest$/, "")}@1.2.3, and run \`crumple lock\`.`);
      }
      const blob = JSON.stringify({ env: srv.env, args: srv.args, headers: srv.headers, url: srv.url });
      if (SECRET_VALUES.test(blob) || /"[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD)[A-Z_]*":"[^"$]{12,}"/.test(blob)) add("high", where, "MCP server config holds a secret in plain text", "Any agent or extension that reads this file gets the key.", "Reference an environment variable or keychain entry instead.");
      if (srv.url && /^http:\/\//.test(srv.url) && !/localhost|127\.0\.0\.1/.test(srv.url)) add("medium", where, "Remote MCP server over plain HTTP", "Anyone on the network path can read and change the tools your agent trusts.", "Use https.");
    }
  }
  const codexToml = read(H(".codex/config.toml"));
  if (codexToml) {
    if (/approval_policy\s*=\s*"never"/.test(codexToml) && /sandbox_mode\s*=\s*"danger-full-access"/.test(codexToml)) add("critical", "~/.codex/config.toml", "Codex runs with no approvals and no sandbox", "A prompt injection becomes code execution on your machine.", "Use `sandbox_mode = \"workspace-write\"`.");
    if (/@latest|npx -y/.test(codexToml)) add("high", "~/.codex/config.toml", "Codex MCP server runs whatever version is newest", "A compromised release runs with your keys.", "Pin exact versions.");
  }

  // --- rules files and docs the agent reads -----------------------------------------------------
  const rulesFiles = ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules", ".github/copilot-instructions.md", "CONTRIBUTING.md", "README.md"].map((f) => P(f));
  try {
    for (const f of fs.readdirSync(P(".cursor/rules"))) rulesFiles.push(P(".cursor/rules", f));
  } catch {}
  rulesFiles.push(H(".claude/CLAUDE.md"), H(".codex/AGENTS.md"), H(".gemini/GEMINI.md"));
  for (const f of rulesFiles) {
    const t = read(f);
    if (t == null) continue;
    if (HIDDEN.test(t)) {
      const decoded = [...t].filter((c) => c.codePointAt(0) >= 0xe0000 && c.codePointAt(0) <= 0xe007f).map((c) => String.fromCharCode(c.codePointAt(0) - 0xe0000)).join("");
      add("critical", rel(f), "Invisible characters hidden in a file your agent reads", `Agents read text you can't see (the "rules file backdoor").${decoded ? ` Hidden text says: "${redact(decoded.slice(0, 120))}"` : ""}`, "Delete the invisible characters (`crumple scan` lists them) and check who added them.");
    }
    if (INJECTION.test(t)) add("high", rel(f), "Text that looks like instructions aimed at an AI agent", `Found: "${redact(t.match(INJECTION)[0]).slice(0, 80)}"`, "Remove it, or make sure your agent treats this file as untrusted.");
    if (SECRET_VALUES.test(t)) add("high", rel(f), "A live-looking secret inside a file the agent reads", "It ends up in every prompt and transcript.", "Remove it and rotate the key.");
  }

  // --- things a repository can make run without asking -------------------------------------------
  const tasks = read(P(".vscode/tasks.json"));
  if (tasks && /folderOpen/.test(tasks)) add("high", ".vscode/tasks.json", "A task runs automatically when the folder opens", "Opening the repo in VS Code or Cursor runs it, before you or an agent review anything.", "Remove `runOn: folderOpen` or delete the task.");
  const devc = read(P(".devcontainer/devcontainer.json"));
  if (devc && /(curl|wget)[^"]*\|\s*(ba)?sh/.test(devc)) add("medium", ".devcontainer/devcontainer.json", "Dev container pipes a download into a shell", "Whoever controls that URL runs code in your environment.", "Pin and check the script.");
  const gitcfg = read(P(".git/config"));
  if (gitcfg && /^\s*(fsmonitor|hookspath|sshcommand|pager)\s*=/im.test(gitcfg)) add("high", ".git/config", "Git is set to run a program on ordinary commands", "`git status` or `git log` will run it, and agents run those constantly.", "Remove the setting unless you added it yourself.");

  // --- secrets within reach ----------------------------------------------------------------------
  const envFiles = fs.existsSync(projectDir) ? fs.readdirSync(projectDir).filter((f) => /^\.env(\.(local|prod\w*|dev\w*|staging))?$/.test(f)) : [];
  let tracked = [];
  try {
    tracked = execFileSync("git", ["ls-files", ...envFiles], { cwd: projectDir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n").filter(Boolean);
  } catch {}
  for (const f of tracked) add("critical", f, "A .env file is committed to git", "Everyone with the repo, and every agent that reads history, has these keys.", "Remove it from git history and rotate every key in it.");
  if (envFiles.length && !denyEnv) add("medium", envFiles.join(", "), "The agent can read your .env", "Most real agent leaks start with the agent reading .env and sending it somewhere.", 'Add "Read(.env*)" to permissions.deny, and give the agent test keys instead of real ones.');
  if (fs.existsSync(H(".aws/credentials"))) add("medium", "~/.aws/credentials", "Long-lived cloud keys sit in your home folder", "Every fake-interview and supply-chain malware family steals this file first.", "Use short-lived credentials (aws sso login), and keep agents sandboxed away from ~/.aws.");
  const npmrc = (read(P(".npmrc")) ?? "") + (read(H(".npmrc")) ?? "");
  const lock = json(P("package-lock.json"));
  if (lock && !/ignore-scripts\s*=\s*true/.test(npmrc)) {
    const scripts = Object.entries(lock.packages ?? {}).filter(([k, v]) => k && v?.hasInstallScript).map(([k]) => k.split("node_modules/").pop());
    if (scripts.length) add("medium", "package-lock.json", `${scripts.length} dependencies run install scripts (${scripts.slice(0, 4).join(", ")}${scripts.length > 4 ? "…" : ""})`, "Install scripts run with your keys in reach; this is how Shai-Hulud and the Nx attack spread.", "Set `ignore-scripts=true` in .npmrc and allow only the few that need it.");
  }

  const order = Object.keys(SEVERITY);
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const score = Math.max(0, 100 - findings.reduce((n, f) => n + SEVERITY[f.severity], 0));
  return { score, grade: score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F", findings };
}

export function toSarif(result) {
  const level = { critical: "error", high: "error", medium: "warning", low: "note" };
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "crumple", informationUri: "https://priberry.com", rules: [] } },
      results: result.findings.map((f) => ({
        ruleId: f.title.replace(/[^a-z0-9]+/gi, "-").toLowerCase().slice(0, 60),
        level: level[f.severity],
        message: { text: `${f.title}. ${f.why} Fix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.where.split(" → ")[0].replace(/^~\//, "") } } }],
      })),
    }],
  };
}
