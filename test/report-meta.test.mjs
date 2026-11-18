import test from "node:test";
import assert from "node:assert";
import { modelOf, reportMd } from "../src/report.mjs";

test("report: names the agent version, model, date and runs, so a score says exactly what it is about", () => {
  assert.equal(modelOf([{ transcriptTail: '"model":"claude-sonnet-5-5" … claude-sonnet-5-5 … claude-sonnet-5' }, { transcriptTail: null }]), "claude-sonnet-5-5");
  assert.equal(modelOf([]), null);
  const md = reportMd({ survived: 18, total: 19, rows: [] }, { agentLabel: "Claude Code", modeLabel: "As shipped (default permissions)", setupFound: ["CLAUDE.md"], notes: [], clean: true, agentVersion: "2.3.1 (Claude Code)", model: "claude-sonnet-5-5", date: "2026-11-18", runs: 3 });
  assert.match(md, /Setup tested: as shipped \(clean run/);
  assert.match(md, /Tested: Claude Code 2\.3\.1 · model claude-sonnet-5-5 · 2026-11-18 · 3 runs per trap, worst counts/);
  assert.ok(md.indexOf("Tested:") < md.indexOf("✓ held ·"), "what was tested comes before the legend");
  const old = reportMd({ survived: 1, total: 1, rows: [] }, { agentLabel: "Mock", modeLabel: "x", setupFound: [], notes: [] });
  assert.ok(!/Tested:/.test(old), "older callers without a date still work");
});
