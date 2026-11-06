// Bug reports without telemetry. Crumple never sends anything by itself: when something goes wrong
// it prints what happened and a link that opens a pre-filled GitHub issue, which the user can read,
// edit and choose to submit.
import os from "node:os";

export const ISSUES = "https://github.com/priberry-data/crumplelab/issues/new";
export const EMAIL = "crumple@priberry.com";

const SECRETS = /\b(sk-ant-[\w-]{8,}|sk-[\w-]{16,}|gh[posu]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|AKIA[0-9A-Z]{16}|AIza[\w-]{30,}|xox[abp]-[\w-]{10,}|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]+)/g;

// Keys, tokens and the user's home folder never make it into a report.
export function redact(text, home = os.homedir()) {
  let s = String(text ?? "").replace(SECRETS, (m) => m.slice(0, 4) + "…[redacted]");
  if (home && home.length > 1) s = s.split(home).join("~");
  return s.replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, "[email]");
}

export function diagnostics({ version, command, agent } = {}) {
  return [
    `crumple ${version}`,
    `command: ${command || "(none)"}`,
    agent ? `agent: ${agent}` : null,
    `node ${process.version} · ${os.platform()} ${os.release()} · ${os.arch()}`,
  ].filter(Boolean).join("\n");
}

export function issueUrl({ title, version, command, agent, error } = {}) {
  const body = [
    "**What happened**",
    "",
    "<!-- What were you doing, and what did you expect? -->",
    "",
    "**Details** (filled in by Crumple; secrets and your home folder are removed)",
    "```",
    diagnostics({ version, command, agent }),
    error ? "\n" + redact(error).slice(-1500) : "",
    "```",
  ].join("\n");
  const q = new URLSearchParams({ title: title || "Bug: ", body, labels: "bug" });
  return `${ISSUES}?${q}`;
}

// The box printed when Crumple itself fails.
export function crashBox({ version, command, agent, error, color = true }) {
  const red = (s) => (color ? `\x1b[31m${s}\x1b[0m` : s);
  const dim = (s) => (color ? `\x1b[2m${s}\x1b[0m` : s);
  const firstLine = redact(String(error).split("\n")[0]).slice(0, 200);
  return [
    "",
    red("  ╔═ crumple crashed ══════════════════════════════════════════╗"),
    `  ${firstLine}`,
    "",
    "  That's our bug, not yours. Please send it to us; it takes one click:",
    `  ${issueUrl({ title: `Crash: ${firstLine.slice(0, 80)}`, version, command, agent, error })}`,
    "",
    dim(`  Nothing was sent. The link opens a pre-filled issue you can read first. Or email ${EMAIL}.`),
    red("  ╚════════════════════════════════════════════════════════════╝"),
    "",
  ].join("\n");
}
