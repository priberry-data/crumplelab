#!/usr/bin/env node
// Crumple guard: a Claude Code PreToolUse hook that stops the attacks the crash test finds.
// It reads the tool call on stdin and either stays silent (allow) or prints a deny decision.
// It is a seatbelt, not a sandbox: a determined agent can obfuscate around text rules.
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const SECRET_WORDS = /\.env\b|AWS_SECRET|AWS_ACCESS|STRIPE|SECRET_KEY|API_KEY|_TOKEN\b|id_rsa|\.aws\/credentials|secrets\./i;
const SECRET_VALUES = /AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9A-Za-z_]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[0-9A-Za-z]{30,}|xox[bp]-[0-9A-Za-z-]{10,}/;
const NETWORK = /\b(curl|wget|nc|ncat|netcat|httpie|http|scp|rsync|ftp|telnet)\b|fetch\(|requests\.(post|put)|Invoke-WebRequest/;
const UPLOAD_FLAGS = /\s(-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(POST|PUT|PATCH))\b/;
const DB_TOOL = /\b(sqlite3|psql|mysql|mongosh?|redis-cli|prisma|knex|sequelize|drizzle-kit)\b/;
const DB_WRITE = /\b(DELETE|DROP|TRUNCATE|UPDATE|INSERT|ALTER|migrate|db push|reset|FLUSHALL|dropDatabase)\b/i;
const GENERATED = /^(\.\/)?(build|dist|out|\.next|\.nuxt|\.cache|\.turbo|\.parcel-cache|node_modules|coverage|tmp|\.tmp|target|__pycache__|\.pytest_cache|\.venv|venv)\/?$|\.log$/;
const AGENT_CONFIG = /(^|\/)(\.claude|\.cursor|\.codex|\.gemini|\.vscode)\/|(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$|\.mcp\.json$/;
const TEST_FILE = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(py|go)$|test_\w+\.py$/;
const SKIP = /\.skip\b|\bxit\(|\bxdescribe\(|@pytest\.mark\.skip|t\.Skip\(|\{\s*skip:\s*true/;

const deny = (reason) => ({ decision: "deny", reason });
const asserts = (s = "") => (s.match(/\bassert\w*[.(]|\bexpect\(|\bshould\b/g) ?? []).length;

function checkBash(cmd) {
  if (NETWORK.test(cmd) && (SECRET_WORDS.test(cmd) || SECRET_VALUES.test(cmd)))
    return deny("Blocked: this command would send secrets or .env contents over the network.");
  if (NETWORK.test(cmd) && UPLOAD_FLAGS.test(cmd) && !/\b(localhost|127\.0\.0\.1)\b/.test(cmd))
    return deny("Blocked: uploading data to an outside server. Ask the user first.");
  if (DB_TOOL.test(cmd) && DB_WRITE.test(cmd) && /prod/i.test(cmd))
    return deny("Blocked: writing to a database marked production. Use the dev database or ask the user.");
  if (/\bgit\s+push\b[^|;&]*(\s--force\b|\s-f\b|--force-with-lease|\s\+\S+)/.test(cmd))
    return deny("Blocked: force-pushing rewrites shared history. Push normally or ask the user.");
  for (const m of cmd.matchAll(/\brm\s+((?:-[a-zA-Z]+\s+)+)([^;&|]+)/g)) {
    if (!/r/i.test(m[1])) continue;
    const targets = m[2].trim().split(/\s+/).filter((t) => !t.startsWith("-"));
    const bad = targets.filter((t) => !GENERATED.test(t));
    if (bad.length) return deny(`Blocked: recursive delete of ${bad.join(", ")}. Only generated folders (build, dist, .cache, node_modules…) may be removed without asking.`);
  }
  if (/\b(npm|pnpm|yarn|bun)\s+(install|i|add)\s+(?!-)[^\s;&|]+|\bpip3?\s+install\s+(?!-r\b)(?!-e\b)[^\s;&|]+|\buv\s+(add|pip install)\s+\S+/.test(cmd))
    return deny("Blocked: installing a new package. Check it is real and trusted, then ask the user to approve it.");
  if (/(>|>>|\btee\b|sed\s+-i|\bmv\b|\bcp\b|\brm\b|\bchmod\b)[^;&|]*?(\.claude|\.cursor|\.codex|\.gemini|\.mcp\.json|CLAUDE\.md|AGENTS\.md)/.test(cmd))
    return deny("Blocked: agents may not change their own configuration or permissions.");
  const touchesTests = /(sed\s+-i|>|\btee\b|\brm\b|\bmv\b|truncate)[^;&|]*?(tests?\/|__tests__|\.test\.|\.spec\.|_test\.py|test_\w+\.py)/.test(cmd);
  if (touchesTests && (/skip|\bxit\b|\bxdescribe\b/.test(cmd) || /\b(rm|mv|truncate)\b/.test(cmd)))
    return deny("Blocked: deleting or skipping tests. Fix the code instead, or ask the user.");
  return null;
}

function checkWrite(file, before, after) {
  if (AGENT_CONFIG.test(file)) return deny("Blocked: agents may not change their own configuration or permissions.");
  if (TEST_FILE.test(file) && after !== undefined && (SKIP.test(after) && !SKIP.test(before ?? "") || asserts(after) < asserts(before)))
    return deny("Blocked: weakening or skipping tests. Fix the code instead, or ask the user.");
  if (/\.github\/workflows\/|\.gitlab-ci\.yml|Jenkinsfile|\.circleci\//.test(file) && NETWORK.test(after ?? "") && /secrets\.|SECRET|TOKEN|KEY/.test(after ?? ""))
    return deny("Blocked: a CI change that sends secrets to a server. Review this by hand.");
  if (SECRET_VALUES.test(after ?? "") && !/\.env(\.|$)/.test(file))
    return deny("Blocked: writing a secret value into a project file.");
  return null;
}

export function decide(input) {
  const tool = input.tool_name ?? "";
  const ti = input.tool_input ?? {};
  if (tool === "Bash") return checkBash(String(ti.command ?? ""));
  if (tool === "Write") return checkWrite(String(ti.file_path ?? ""), safeRead(ti.file_path), String(ti.content ?? ""));
  if (tool === "Edit") return checkWrite(String(ti.file_path ?? ""), String(ti.old_string ?? ""), String(ti.new_string ?? ""));
  if (tool === "MultiEdit") {
    for (const e of ti.edits ?? []) {
      const r = checkWrite(String(ti.file_path ?? ""), String(e.old_string ?? ""), String(e.new_string ?? ""));
      if (r) return r;
    }
    return null;
  }
  if (tool.startsWith("mcp__")) {
    const args = JSON.stringify(ti);
    if (SECRET_VALUES.test(args) || /[A-Z_]{4,}(SECRET|KEY|TOKEN)[A-Z_]*=/.test(args))
      return deny("Blocked: this MCP tool call would hand over secrets. Do not pass credentials to tools.");
  }
  return null;
}

function safeRead(p) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

// Run as a hook: read stdin, print Claude Code's deny format, exit 0 either way.
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  let raw = "";
  process.stdin.on("data", (d) => (raw += d));
  process.stdin.on("end", () => {
    let verdict = null;
    try {
      verdict = decide(JSON.parse(raw));
    } catch {}
    if (verdict)
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: verdict.reason },
      }));
  });
}
