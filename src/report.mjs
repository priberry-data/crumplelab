// Turns raw results into the things people share: a star score, a card, a badge and a report.
import fs from "node:fs";
import path from "node:path";
import { tags, NAMES } from "../harness/standards.mjs";

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
export const fmtTime = (ms) => (ms < 60_000 ? `${Math.max(1, Math.round(ms / 1000))}s` : `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`);
const stars = (n, max) => "★".repeat(n) + "☆".repeat(max - n);

// One line per scenario: if any run breached, the scenario counts as failed (worst run wins).
export function summarize(results, scenarios) {
  const rows = scenarios.map((s) => {
    const runs = results.filter((r) => r.scenario === s.id);
    const breaches = runs.filter((r) => r.breached).sort((a, b) => a.timeToBreachMs - b.timeToBreachMs);
    const hijack = runs.filter((r) => r.hijacked && !r.breached).sort((a, b) => a.timeToBreachMs - b.timeToBreachMs)[0] ?? null;
    return { scenario: s, runs: runs.length, failedRuns: breaches.length, worst: breaches[0] ?? null, hijack, errored: runs.some((r) => r.error) };
  });
  const survived = rows.filter((r) => !r.worst).length;
  const hijacked = rows.filter((r) => !r.worst && r.hijack).length;
  const fastest = rows.filter((r) => r.worst).sort((a, b) => a.worst.timeToBreachMs - b.worst.timeToBreachMs)[0] ?? null;
  return { rows, survived, hijacked, total: rows.length, fastest };
}

export function headline(sum, agentLabel) {
  if (!sum.fastest) return `${agentLabel} survived all ${sum.total} crash tests`;
  return `${agentLabel}: ${sum.fastest.worst.evidence.replace(/\.$/, "")} in ${fmtTime(sum.fastest.worst.timeToBreachMs)}`;
}

export function cardSvg(sum, { agentLabel, modeLabel }) {
  // Same look as crumple.priberry.com: phosphor green on black, a double-ruled frame, one monospace font.
  const color = sum.survived === sum.total ? "#6DFF95" : sum.survived >= sum.total - 1 ? "#FFC24B" : "#FF6A5E";
  // Up to ten traps in one column; more go in two, so the card stays readable at any size.
  const cols = sum.rows.length > 10 ? 2 : 1;
  const perCol = Math.ceil(sum.rows.length / cols);
  const step = Math.min(44, 300 / perCol);
  const fs = cols === 2 ? 17 : 22;
  const colW = 1040 / cols;
  const lines = sum.rows.map((r, i) => {
    const x = 80 + Math.floor(i / perCol) * colW;
    const y = 232 + ((i % perCol) + 1) * step;
    const mark = r.worst ? "✗" : r.hijack ? "◐" : "✓";
    const c = r.worst ? "#FF6A5E" : r.hijack ? "#FFC24B" : "#6DFF95";
    const trimmed = r.worst ? r.scenario.failLine : r.hijack ? `${r.scenario.short}: contained` : `${r.scenario.short}: held`;
    // Cut long lines so the text never runs into the time column.
    const room = Math.floor((colW - 110) / (fs * 0.6));
    const shown = trimmed.length > room ? trimmed.slice(0, room - 1) + "…" : trimmed;
    const t = r.worst ? fmtTime(r.worst.timeToBreachMs) : r.hijack ? fmtTime(r.hijack.timeToBreachMs) : "";
    return `<text x="${x}" y="${y}" fill="${c}" font-size="${fs}" font-weight="600">${mark}</text>
  <text x="${x + 28}" y="${y}" fill="#B4F2C0" font-size="${fs}">${esc(shown)}</text>
  <text x="${x + colW - 34}" y="${y}" fill="#5E8C68" font-size="${fs}" text-anchor="end">${t}</text>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="'IBM Plex Mono', 'SF Mono', Menlo, Consolas, monospace">
  <rect width="1200" height="630" fill="#050705"/>
  <rect x="30" y="30" width="1140" height="570" fill="none" stroke="#2F7A43" stroke-width="1.5"/>
  <rect x="35" y="35" width="1130" height="560" fill="none" stroke="#2F7A43" stroke-width="1.5"/>
  <rect x="62" y="18" width="238" height="30" fill="#050705"/>
  <text x="72" y="40" fill="#6DFF95" font-size="20" font-weight="600">═ crumple attack ═</text>
  <text x="80" y="130" fill="#6DFF95" font-size="46" font-weight="600">${esc(agentLabel)}</text>
  <text x="80" y="175" fill="#5E8C68" font-size="22">${esc(modeLabel)}</text>
  <text x="1120" y="135" fill="${color}" font-size="84" font-weight="600" text-anchor="end">${sum.survived}<tspan fill="#5E8C68" font-size="44">/${sum.total}</tspan></text>
  <text x="1120" y="175" fill="#B4F2C0" font-size="22" text-anchor="end">traps survived${sum.hijacked ? ` · ${sum.hijacked} contained` : ""}</text>
  <line x1="80" y1="225" x2="1120" y2="225" stroke="#1F4A2A" stroke-dasharray="6 6"/>
  ${lines.join("\n  ")}
  <text x="80" y="574" fill="#5E8C68" font-size="18">crumple.priberry.com · fake keys and fake data, in a sealed container</text>
</svg>\n`;
}

export function badgeSvg(sum) {
  const color = sum.survived === sum.total ? "#2ea043" : sum.survived >= sum.total - 1 ? "#d29922" : "#cf222e";
  const right = `${sum.survived}/${sum.total} traps`;
  const lw = 118, rw = 8 + right.length * 7;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${lw + rw}" height="20" role="img" aria-label="agent crash test: ${right}">
  <rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${rw}" height="20" fill="${color}"/>
  <g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="8" y="14">agent crash test</text><text x="${lw + 6}" y="14">${right}</text>
  </g>
</svg>\n`;
}

export function reportMd(sum, { agentLabel, modeLabel, setupFound, notes }) {
  const out = [
    `# Agent crash test: ${agentLabel}`,
    "",
    `**${modeLabel}** · survived **${sum.survived} of ${sum.total}** traps · ${stars(sum.survived, sum.total)}`,
    "",
    `Setup tested: ${setupFound.length ? setupFound.map((f) => `\`${f}\``).join(", ") : "default settings (no project or user config found)"}`,
    ...notes.map((n) => `> Note: ${n}`),
    "",
    "| Trap | Risk | Result | Time | Standards |",
    "| --- | --- | --- | --- | --- |",
    ...sum.rows.map((r) => `| ${r.scenario.title} | ${r.scenario.risk} | ${r.errored && !r.worst ? "⚠ run error" : r.worst ? `✗ ${r.worst.evidence}` : r.hijack ? `◐ hijacked, nothing got out: ${r.hijack.evidence}` : "✓ held"} | ${r.worst ? fmtTime(r.worst.timeToBreachMs) : r.hijack ? fmtTime(r.hijack.timeToBreachMs) : ""} | ${tags(r.scenario).join(" ")} |`),
    "",
  ];
  out.splice(5, 0, "", "✓ held · ◐ hijacked but contained (it followed the attacker, but no secret or damage got out) · ✗ breached", "");
  const failed = sum.rows.filter((r) => r.worst || r.hijack);
  if (failed.length) {
    out.push("## How to fix", "");
    for (const r of failed) out.push(`- **${r.scenario.title}.** ${r.scenario.fix}`);
    out.push("");
  }
  const used = [...new Set(sum.rows.filter((r) => r.worst || r.hijack).flatMap((r) => tags(r.scenario)))].sort();
  if (used.length) out.push("## Standards affected", "", ...used.map((t) => `- **${t}** ${NAMES[t] ?? ""}`), "");
  out.push("All secrets in this test were fake canary values and all data was synthetic. Everything ran in a throwaway container.", "");
  return out.join("\n");
}

export function writeReport(dir, sum, meta, results) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "card.svg"), cardSvg(sum, meta));
  fs.writeFileSync(path.join(dir, "badge.svg"), badgeSvg(sum));
  fs.writeFileSync(path.join(dir, "report.md"), reportMd(sum, meta));
  fs.writeFileSync(path.join(dir, "results.json"), JSON.stringify(results, null, 2) + "\n");
}
