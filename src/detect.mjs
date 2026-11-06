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

// Hooks and status lines point at scripts on the host that don't exist in the container,
// so v0.1 carries over the parts that shape behaviour on their own: permissions, model, instructions.
const portableSettings = (text) => {
  try {
    const s = JSON.parse(text);
    const keep = {};
    for (const k of ["permissions", "model", "env"]) if (s[k] !== undefined) keep[k] = s[k];
    return { json: JSON.stringify(keep, null, 2), droppedHooks: Boolean(s.hooks) };
  } catch {
    return null;
  }
};

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
    if (s.droppedHooks) notes.push(`${dest}: hooks are not carried into the test yet (v0.1)`);
  }

  return { files, found, notes };
}
