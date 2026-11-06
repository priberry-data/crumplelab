// Finds the user's own agent setup so the crash test runs THEIR configuration, not a default one.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const read = (p) => {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
};

const isCrumpleGuard = (cmd = "") => /guard\.mjs|crumplelab guard/.test(cmd);

// Most hooks point at scripts on the host that don't exist in the container, so they stay behind.
// The Crumple guard is the exception: the container has its own copy, so it is carried over and re-pointed.
const portableSettings = (text) => {
  try {
    const s = JSON.parse(text);
    const keep = {};
    for (const k of ["permissions", "model", "env", "sandbox", "enableAllProjectMcpServers", "allowManagedHooksOnly", "disableAllHooks"]) if (s[k] !== undefined) keep[k] = s[k];
    let droppedHooks = false;
    if (s.hooks) {
      const hooks = {};
      for (const [event, groups] of Object.entries(s.hooks)) {
        const kept = [];
        for (const g of groups ?? []) {
          const ours = (g.hooks ?? []).filter((h) => isCrumpleGuard(h.command));
          if (ours.length < (g.hooks ?? []).length) droppedHooks = true;
          if (ours.length) kept.push({ ...g, hooks: ours.map((h) => ({ ...h, command: "node /opt/crumple/guard.mjs" })) });
        }
        if (kept.length) hooks[event] = kept;
      }
      if (Object.keys(hooks).length) keep.hooks = hooks;
    }
    return { json: JSON.stringify(keep, null, 2), droppedHooks };
  } catch {
    return null;
  }
};

// Where Claude Code reads settings that users and projects can't override.
export const MANAGED_SETTINGS = process.env.CRUMPLE_MANAGED_SETTINGS
  ?? (process.platform === "darwin" ? "/Library/Application Support/ClaudeCode/managed-settings.json" : "/etc/claude-code/managed-settings.json");

export function detectClaudeSetup(projectDir) {
  const files = {};
  const found = [];
  const notes = [];

  for (const name of ["CLAUDE.md", "AGENTS.md"]) {
    const text = read(path.join(projectDir, name));
    if (text) {
      files[name] = text;
      found.push(name);
    }
  }
  const userMd = read(path.join(os.homedir(), ".claude", "CLAUDE.md"));
  if (userMd) {
    files["~/.claude/CLAUDE.md"] = userMd;
    found.push("~/.claude/CLAUDE.md");
  }

  for (const [src, dest] of [
    [path.join(projectDir, ".claude", "settings.json"), ".claude/settings.json"],
    [path.join(projectDir, ".claude", "settings.local.json"), ".claude/settings.local.json"],
    [path.join(os.homedir(), ".claude", "settings.json"), "~/.claude/settings.json"],
  ]) {
    const text = read(src);
    if (!text) continue;
    const s = portableSettings(text);
    if (!s) continue;
    files[dest] = s.json;
    found.push(dest);
    if (s.droppedHooks) notes.push(`${dest}: your own hooks are not carried into the test yet (only the Crumple guard is)`);
    if (JSON.parse(s.json).sandbox?.enabled) notes.push(`${dest}: sandbox is on, but Claude Code's sandbox can't start inside the test container, so traps measure the other layers`);
  }
  const managed = read(MANAGED_SETTINGS);
  const m = managed && portableSettings(managed);
  if (m) {
    files["@managed"] = m.json;
    found.push("managed settings");
  }

  return { files, found, notes };
}
