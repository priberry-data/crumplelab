import test from "node:test";
import assert from "node:assert";
import { modelOf, reportMd, summarize, headline, cardSvg } from "../src/report.mjs";

test("report: names the agent version, model, date and runs, so a score says exactly what it is about", () => {
  assert.equal(modelOf([{ transcriptTail: '"model":"claude-sonnet-5-5" … claude-sonnet-5-5 … claude-sonnet-5' }, { transcriptTail: null }]), "claude-sonnet-5-5");
  assert.equal(modelOf([]), null);
  const md = reportMd({ survived: 18, total: 19, rows: [] }, { agentLabel: "Claude Code", modeLabel: "As shipped (default permissions)", setupFound: ["CLAUDE.md"], notes: [], clean: true, agentVersion: "2.3.1 (Claude Code)", model: "claude-sonnet-5-5", date: "2026-11-18", runs: 3 });
  assert.match(md, /Setup tested: as shipped \(clean run/);
  assert.match(md, /Tested: Claude Code 2\.3\.1 · model claude-sonnet-5-5 · 2026-11-18 · 3 runs per trap, worst counts/);
  assert.ok(md.indexOf("Tested:") < md.indexOf("✓ held ("), "what was tested comes before the legend");
  const old = reportMd({ survived: 1, total: 1, rows: [] }, { agentLabel: "Mock", modeLabel: "x", setupFound: [], notes: [] });
  assert.ok(!/Tested:/.test(old), "older callers without a date still work");
});

test("report: a trap the agent never got to is 'not reached', never 'held', and its promise is 'not tested'", () => {
  const scen = (id) => ({ id, title: id, short: id, failLine: `${id} failed`, risk: "r", fix: "f", promise: `promise of ${id}` });
  const scenarios = [scen("a"), scen("b"), scen("c"), scen("d")];
  const results = [
    { scenario: "a", breached: false, hijacked: false, reached: true },
    { scenario: "b", breached: false, hijacked: false, reached: false },
    { scenario: "b", breached: false, hijacked: false, reached: true }, // reached in one of two runs: that run held
    { scenario: "c", breached: false, hijacked: false, reached: false },
    { scenario: "d", breached: false, hijacked: false, reached: null }, // older pack trap: no way to tell, reads as before
  ];
  const sum = summarize(results, scenarios);
  assert.equal(sum.survived, 3);
  assert.equal(sum.notReached, 1);
  assert.ok(sum.rows.find((r) => r.scenario.id === "c").notReached);
  assert.match(headline(sum, "Mock"), /held in all 3 traps it reached; 1 never reached/);
  const md = reportMd(sum, { agentLabel: "Mock", modeLabel: "x", setupFound: [], notes: [] });
  assert.match(md, /○ not reached/);
  assert.match(md, /○ not tested: promise of c/);
  assert.match(md, /✓ kept: promise of a/);
  assert.match(cardSvg(sum, { agentLabel: "Mock", modeLabel: "x" }), /c: not reached/);
});
